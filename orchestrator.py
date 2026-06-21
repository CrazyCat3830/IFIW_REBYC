"""
מחלקת Orchestrator היא הרכיב המרכזי של המערכת.

היא אחראית על תיאום הפעילות בין כל רכיבי המערכת:
- לכידת תעבורת רשת
- עיבוד מנות (Packets)
- ניהול Flows
- זיהוי מתקפות ואנומליות
- שמירת נתונים במסד הנתונים
- שמירת התראות ב-Firebase
- יצירת קבצי ראיות (PCAP)
- הפעלת מדיניות תגובה (Policy)

המחלקה משמשת כנקודת החיבור המרכזית בין מנוע הניטור, מסד הנתונים וממשק המשתמש.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
from collections import deque
from datetime import datetime, timedelta

from scapy.utils import wrpcap

from anomaly import update_and_check_anomaly
from attacks import (
    update_and_check_arpspoof,
    update_and_check_dhcp_spoof,
    update_and_check_dns_poison,
    update_and_check_eviltwin,
    update_and_check_flood,
    update_and_check_portscan,
    update_and_check_synflood,
)
from database import Database
from firebase_alerts import save_alert
from flows import FlowStats, compute_flow_key
from forensics import create_evidence_bundle
from messages import MessageBus
from packet import Packet
from poc_sniffer import normalize_packet
from policy import decide_policy


class Orchestrator:
    def __init__(
        self,
        db_path: str = "DB.db",
        evidence_dir: str = "evidence",
        evidence_max_packets: int = 2000,
        firebase_uid=None,
        firebase_token=None,
        packet_db_ttl_seconds: int = 3600,
        flow_db_ttl_seconds: int = 1800,
        flow_idle_ttl_seconds: int = 300,
        retention_interval_seconds: int = 60,
        processing_queue_maxsize: int = 20000,
        worker_count: int | None = None,
        queue_warning_interval_seconds: float = 2.0,
    ):
        self.firebase_uid = firebase_uid
        self.firebase_token = firebase_token
        self.running = False
        self.thread = None
        self.worker_threads: list[threading.Thread] = []
        self.maintenance_thread = None

        self.db_path = db_path
        self.db = Database(db_path)
        self.msg = MessageBus(maxlen=1000)
        self._blocked_until: dict[str, datetime] = {}
        self.flows: dict = {}
        self._flows_lock = threading.Lock()

        self.evidence_dir = evidence_dir
        self.evidence_max_packets = evidence_max_packets
        self._buf_by_src: dict[str, deque] = {}
        self._buf_by_dst: dict[str, deque] = {}
        os.makedirs(self.evidence_dir, exist_ok=True)

        self.jsonl_path = None
        self.processing_queue: queue.Queue = queue.Queue(maxsize=int(processing_queue_maxsize))

        cpu = os.cpu_count() or 4
        if worker_count is None:
            worker_count = max(2, min(4, cpu))
        self.worker_count = int(worker_count)
        self.queue_warning_interval_seconds = float(queue_warning_interval_seconds)
        self._last_queue_warn_ts = 0.0
        self._suppressed_queue_drops = 0
        self._dropped_packets_total = 0
        self._metrics_lock = threading.Lock()

        self.packet_db_ttl_seconds = int(packet_db_ttl_seconds)
        self.flow_db_ttl_seconds = int(flow_db_ttl_seconds)
        self.flow_idle_ttl_seconds = int(flow_idle_ttl_seconds)
        self.retention_interval_seconds = int(retention_interval_seconds)
        self._last_retention_run = 0.0

    def start_sniff(self, iface=None):
        """
        Starts the monitoring engine.
        Creates worker threads, starts the maintenance thread
        and launches the packet capture loop.
        """
        if self.running:
            return
        self.running = True
        self.worker_threads = [
            threading.Thread(target=self._processing_loop, name=f"orch-worker-{i}", daemon=True)
            for i in range(self.worker_count)
        ]
        for t in self.worker_threads:
            t.start()
        self.maintenance_thread = threading.Thread(target=self._maintenance_loop, daemon=True)
        self.maintenance_thread.start()
        self.thread = threading.Thread(target=self._sniff_loop, args=(iface,), daemon=True)
        self.thread.start()
        self.msg.publish(
            "INFO",
            "Sniffer started",
            f"Interface={iface or 'default'} | workers={self.worker_count} | queue={self.processing_queue.maxsize}",
        )
        print(f"[orch] Sniffer started on {iface or 'default interface'} with {self.worker_count} workers")

    def stop_sniff(self):
        """
        Stops packet capture and signals all background threads
        to finish their work and exit.
        """
        if not self.running:
            return
        self.msg.publish("INFO", "Sniffer stopping")
        print("[orch] Stopping sniffer...")
        self.running = False

    def _sniff_loop(self, iface):
        """
        Captures raw packets using Scapy and places them into
        the processing queue for asynchronous handling.
        """
        from scapy.all import sniff

        def on_raw_packet(pkt):
            if not self.running:
                return
            try:
                self.processing_queue.put_nowait(pkt)
            except queue.Full:
                self._handle_queue_full()

        sniff(iface=iface, prn=on_raw_packet, store=False, stop_filter=lambda _: not self.running)

    def _handle_queue_full(self):
        """
        Handles processing queue overflow and throttles warning messages.
        """
        now = time.time()
        publish_now = False
        with self._metrics_lock:
            self._dropped_packets_total += 1
            self._suppressed_queue_drops += 1
            if now - self._last_queue_warn_ts >= self.queue_warning_interval_seconds:
                count = self._suppressed_queue_drops
                self._suppressed_queue_drops = 0
                self._last_queue_warn_ts = now
                publish_now = True
            else:
                count = 0
        if publish_now:
            qsize = self.processing_queue.qsize()
            self.msg.publish(
                "WARN",
                "Packet dropped",
                f"processing queue full | dropped={count} | qsize={qsize}/{self.processing_queue.maxsize}",
            )

    def _processing_loop(self):
        """
        Worker thread loop.

        Continuously pulls packets from the processing queue
        and processes them until monitoring stops.
        """
        while self.running or not self.processing_queue.empty():
            try:
                raw_pkt = self.processing_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                self._process_one_packet(raw_pkt)
            except Exception as e:
                print(f"[orch] processing error: {e}")
            finally:
                self.processing_queue.task_done()

    def _process_one_packet(self, raw_pkt):
        """
        Processes a single packet through the monitoring pipeline.
        Steps:
        1. Normalize packet fields
        2. Apply blocking policy
        3. Store packet evidence
        4. Save packet to database
        5. Update flow statistics
        6. Run attack detection engines
        7. Handle generated alerts
        """
        try:
            p: Packet = normalize_packet(raw_pkt)
        except Exception as e:
            print(f"[orch] normalize error: {e}")
            return

        if p.src_ip and self._is_blocked(p.src_ip):
            self.msg.publish("ACTION", "Dropped packet (blocked)", f"src_ip={p.src_ip}")
            return

        self._buffer_evidence(raw_pkt, p)
        packet_id = None
        try:
            packet_id = self.db.insert_packet(p, scan_id=None)
        except Exception as e:
            print(f"[orch] DB insert packet error: {e}")

        self._log_jsonl(p)
        self._update_flow(p)

        for a in self._run_detections(p):
            self._handle_alert(a, p, packet_id)

    def _maintenance_loop(self):
        """
        Periodic background maintenance task.

        Removes expired flows, performs retention cleanup
        and reports queue overflow statistics.
        """
        while self.running:
            try:
                self._cleanup_in_memory_flows()
                now = time.time()
                if now - self._last_retention_run >= self.retention_interval_seconds:
                    self._last_retention_run = now
                    self.run_retention_cleanup()
                self._flush_suppressed_queue_drop_message(force=False)
            except Exception as e:
                print(f"[orch] maintenance error: {e}")
            time.sleep(2)
        self._flush_suppressed_queue_drop_message(force=True)

    def _flush_suppressed_queue_drop_message(self, force: bool):
        with self._metrics_lock:
            if self._suppressed_queue_drops <= 0:
                return
            now = time.time()
            if not force and now - self._last_queue_warn_ts < self.queue_warning_interval_seconds:
                return
            count = self._suppressed_queue_drops
            self._suppressed_queue_drops = 0
            self._last_queue_warn_ts = now
        self.msg.publish(
            "WARN",
            "Packet dropped",
            f"processing queue full | dropped={count} | qsize={self.processing_queue.qsize()}/{self.processing_queue.maxsize}",
        )

    def _get_buf(self, mapping: dict, key: str):
        if key not in mapping:
            mapping[key] = deque(maxlen=self.evidence_max_packets)
        return mapping[key]

    def _buffer_evidence(self, raw_pkt, p: Packet):
        """
        Stores recent packets in memory buffers that may later
        be exported as forensic evidence.
        """
        if p.src_ip:
            self._get_buf(self._buf_by_src, p.src_ip).append(raw_pkt)
        if p.dst_ip:
            self._get_buf(self._buf_by_dst, p.dst_ip).append(raw_pkt)
        arp_ip = (p.meta or {}).get("arp_ip")
        if arp_ip:
            self._get_buf(self._buf_by_src, arp_ip).append(raw_pkt)
        ssid = (p.meta or {}).get("wifi_ssid")
        if ssid:
            self._get_buf(self._buf_by_src, ssid).append(raw_pkt)

    def _export_pcap(self, key: str, alert_type: str, alert_id: int) -> str | None:
        """
        Exports buffered packets into a PCAP file associated
        with a specific alert.
        """
        pkts = None
        if key in self._buf_by_src and self._buf_by_src[key]:
            pkts = list(self._buf_by_src[key])
        elif key in self._buf_by_dst and self._buf_by_dst[key]:
            pkts = list(self._buf_by_dst[key])
        if not pkts:
            return None
        safe_key = key.replace(":", "_").replace("/", "_").replace(" ", "_")
        path = os.path.join(self.evidence_dir, f"{alert_id:06d}_{alert_type}_{safe_key}.pcap")
        try:
            wrpcap(path, pkts)
            return path
        except Exception as e:
            print(f"[orch] PCAP export error: {e}")
            return None

    def _update_flow(self, p: Packet):
        """
        Updates flow statistics for the packet and periodically
        persists flow data to the database.
        """
        key = compute_flow_key(p)
        if not key:
            return
        with self._flows_lock:
            f = self.flows.get(key)
            if f is None:
                f = FlowStats.from_packet(key, p)
                self.flows[key] = f
            f.update(p)
            if f.packet_count % 500 == 0:
                try:
                    self.db.insert_flow(f, scan_id=None)
                except Exception as e:
                    print(f"[orch] DB insert flow error: {e}")

    def _cleanup_in_memory_flows(self):
        """
        Removes inactive flows that exceeded the configured idle timeout.
        """
        cutoff = datetime.utcnow() - timedelta(seconds=self.flow_idle_ttl_seconds)
        with self._flows_lock:
            stale = [k for k, f in self.flows.items() if f.last_ts < cutoff]
            for k in stale:
                del self.flows[k]

    def _run_detections(self, p: Packet) -> list[dict]:
        """
        Executes all detection engines and collects any alerts
        generated for the current packet.
        """
        out = []
        for fn in (
            update_and_check_portscan,
            update_and_check_arpspoof,
            update_and_check_synflood,
            update_and_check_dns_poison,
            update_and_check_dhcp_spoof,
            update_and_check_anomaly,
            update_and_check_flood,
            update_and_check_eviltwin,
        ):
            try:
                alert = fn(p)
                if alert:
                    out.append(alert)
            except Exception as e:
                print(f"[orch] detector error in {fn.__name__}: {e}")
        return out

    def _handle_alert(self, alert: dict, p: Packet, packet_id: int | None):
        """
        Processes a detected security event.

        Creates the alert record, exports evidence,
        stores cloud notifications and applies response policy.
        """
        alert_type = alert.get("type", "UNKNOWN")
        severity = int(alert.get("severity", 5))
        desc = alert.get("description", "")
        ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"

        try:
            from geoip import lookup_ip
            geo = lookup_ip(p.src_ip) if p.src_ip else None
            if geo:
                country = geo.get("country") or "Unknown"
                city = geo.get("city") or "Unknown"
                desc += f" | Origin: {country} / {city}"
        except Exception:
            pass

        evidence_key = alert.get("evidence_key") or p.src_ip or p.dst_ip or "unknown"
        try:
            alert_id = self.db.insert_alert(packet_id, alert_type, severity, desc, ts, pcap_path=None)
        except Exception as e:
            print(f"[orch] DB insert alert error: {e}")
            return

        pcap_path = self._export_pcap(evidence_key, alert_type, alert_id)
        if pcap_path:
            try:
                self.db.update_alert_pcap_path(alert_id, pcap_path)
            except Exception as e:
                print(f"[orch] DB update alert pcap_path error: {e}")

        save_alert(
            self.firebase_uid,
            self.firebase_token,
            alert_id,
            {
                "type": alert_type,
                "severity": severity,
                "description": desc,
                "timestamp": ts,
                "pcap_path": pcap_path,
            },
        )

        self.msg.publish("ALERT", f"{alert_type} (sev={severity})", desc, alert_id=alert_id)
        print(f"[ALERT] #{alert_id} {alert_type} sev={severity}: {desc}" + (f" (pcap={pcap_path})" if pcap_path else ""))
        self._apply_policy(alert_type, severity, p)

    def _apply_policy(self, alert_type: str, severity: int, p: Packet) -> None:
        """
        Applies the response policy associated with a detected alert.

        Supported actions include notification, temporary blocking
        and rate limiting.
        """
        pr = decide_policy(alert_type, severity)
        if pr.action == "NONE":
            return
        target_ip = p.src_ip or p.dst_ip
        if pr.action == "BLOCK" and target_ip and pr.ttl_seconds:
            unblock = datetime.utcnow() + timedelta(seconds=int(pr.ttl_seconds))
            self._blocked_until[target_ip] = unblock
            try:
                self.db.add_list_entry("blacklist", target_ip, f"{pr.reason}; ttl={pr.ttl_seconds}s")
            except Exception as e:
                print(f"[orch] blacklist log error: {e}")
            self.msg.publish("ACTION", "Applied policy: BLOCK", f"ip={target_ip} ttl={pr.ttl_seconds}s")
        elif pr.action == "RATE_LIMIT" and target_ip and pr.ttl_seconds:
            self.msg.publish("ACTION", "Applied policy: RATE_LIMIT", f"target={target_ip} ttl={pr.ttl_seconds}s")
        elif pr.action == "NOTIFY":
            self.msg.publish("WARN", "Policy: NOTIFY", pr.reason)

    def _is_blocked(self, src_ip: str) -> bool:
        """
        Checks whether an IP address is currently blocked by policy.
        """
        until = self._blocked_until.get(src_ip)
        if not until:
            return False
        if datetime.utcnow() >= until:
            del self._blocked_until[src_ip]
            return False
        return True

    def consume_messages(self):
        """
        Returns and clears pending runtime messages from the message bus.
        """
        return self.msg.consume_all()

    def _log_jsonl(self, p: Packet):
        """
        Appends packet data to an optional JSONL audit log.
        """
        if not self.jsonl_path:
            return
        try:
            with open(self.jsonl_path, "a", encoding="utf-8") as f:
                json.dump(p.to_dict(), f, ensure_ascii=False)
                f.write("\n")
        except Exception as e:
            print(f"[orch] JSONL log error: {e}")

    def export_forensics(self, user_email: str, alert_id: int):
        """
        Creates a complete forensic evidence bundle for a selected alert.
        """
        return create_evidence_bundle(db=self.db, user_email=user_email, incident_id=alert_id)

    def run_retention_cleanup(self):
        """
        Removes expired packet and flow records according to
        the configured retention policy.
        """
        deleted_packets = self.db.delete_old_packets(self.packet_db_ttl_seconds) if self.packet_db_ttl_seconds > 0 else 0
        deleted_flows = self.db.delete_old_flows(self.flow_db_ttl_seconds) if self.flow_db_ttl_seconds > 0 else 0
        if deleted_packets or deleted_flows:
            self.msg.publish("INFO", "Retention cleanup", f"packets={deleted_packets}, flows={deleted_flows}")

    def get_runtime_stats(self) -> dict:
        """
        Returns live runtime statistics used by the dashboard.
        """
        with self._metrics_lock:
            dropped_packets_total = self._dropped_packets_total
        with self._flows_lock:
            active_flows = len(self.flows)
        return {
            "running": self.running,
            "queue_size": self.processing_queue.qsize(),
            "queue_maxsize": self.processing_queue.maxsize,
            "worker_count": self.worker_count,
            "dropped_packets_total": dropped_packets_total,
            "active_flows": active_flows,
        }
