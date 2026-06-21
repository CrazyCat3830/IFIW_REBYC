"""
קובץ זה אחראי על ניהול מסד הנתונים המקומי של המערכת באמצעות SQLite.

המסד המקומי שומר את הנתונים המלאים של המערכת:
- scans: מידע על סריקות שבוצעו
- packets: חבילות רשת שנקלטו, כולל raw_bytes לשחזור ראיות
- alerts: התראות שזוהו על ידי מנועי הזיהוי
- audit: רישום פעולות ייצוא ראיות לצורך מעקב
- rules: טבלת חוקים עתידית/כללית לזיהוי
- whitelist_blacklist: רשימות כתובות מאושרות או חסומות
- flows: סטטיסטיקות על תקשורת בין שני קצוות ברשת

הקובץ מספק פונקציות להוספה, שליפה, עדכון וניקוי נתונים,
ומשמש את ה-Orchestrator, ה-Dashboard ומנגנון ה-Forensics.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Optional

from packet import Packet
from flows import FlowStats


class Database:
    def __init__(self, db_name: str):
        """
        Opens a SQLite database connection and prepares the database schema.
        """
        self.db_name = db_name
        # Reentrant lock protects SQLite access from multiple threads
        self._lock = threading.RLock()
        # Allows database access from different threads; protected by self._lock
        self.connection = sqlite3.connect(self.db_name, check_same_thread=False)
        # Allows accessing query results by column name
        self.connection.row_factory = sqlite3.Row
        # Improves SQLite reliability and concurrency using Write-Ahead Logging
        self.connection.execute("PRAGMA journal_mode=WAL;")
        # Enables foreign key constraints in SQLite
        self.connection.execute("PRAGMA foreign_keys=ON;")
        # Waits up to 5 seconds if the database is temporarily locked
        self.connection.execute("PRAGMA busy_timeout=5000;")

        self._ensure_schema()
        self._ensure_migrations()

    # ---------------- internal helpers ----------------
    def _execute(self, sql: str, params: tuple = ()):
        """
        Executes an SQL command that modifies the database.
        """
        # Prevent multiple threads from accessing the database simultaneously
        with self._lock:
            # Creates a cursor (SQL command handler) for interacting with the database
            cursor = self.connection.cursor()
            # Execute the SQL command using parameterized values
            # Parameters are passed separately to avoid SQL injection
            cursor.execute(sql, params)
            # Permanently save all pending database changes to DB.db
            self.connection.commit()
            # Return the cursor so the caller can access metadata such as last inserted row ID
            return cursor

    def _query_all(self, sql: str, params: tuple = ()):
        """
        Executes a SELECT query and returns all matching rows.
        """
        with self._lock:
            cursor = self.connection.cursor()
            # Execute query and return all matching rows
            return cursor.execute(sql, params).fetchall()

    def _query_one(self, sql: str, params: tuple = ()):
        """
        Executes a SELECT query and returns one matching row.
        """
        with self._lock:
            cursor = self.connection.cursor()
            # Execute query and return only the first matching row
            return cursor.execute(sql, params).fetchone()

    @staticmethod
    def _sqlite_ts_expr(column_name: str) -> str:
        return f"datetime(replace(replace({column_name}, 'T', ' '), 'Z', ''))"

    # ---------------- Schema ----------------
    def _ensure_schema(self) -> None:
        """
        Creates all required database tables and indexes if they do not exist.
        """
        with self._lock:
            cursor = self.connection.cursor()

            cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
                scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                scan_description TEXT,
                scan_date TEXT,
                router_mac TEXT
            )""")

            cursor.execute("""CREATE TABLE IF NOT EXISTS packets (
                packet_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto INTEGER,
                proto_name TEXT,
                flags TEXT,
                payload_len INTEGER,
                raw_len INTEGER,
                summary TEXT,
                scan_id INTEGER,
                meta TEXT,
                raw_bytes BLOB,
                flow_key TEXT
            )""")

            cursor.execute("""CREATE TABLE IF NOT EXISTS alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                packet_id INTEGER,
                alert_type TEXT,
                severity INTEGER,
                description TEXT,
                timestamp TEXT,
                pcap_path TEXT
            )""")

            cursor.execute("""CREATE TABLE IF NOT EXISTS audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT,
                action TEXT,
                params_json TEXT,
                created_at TEXT,
                artifact_path TEXT,
                artifact_sha256 TEXT
            )""")

            cursor.execute("""CREATE TABLE IF NOT EXISTS rules (
                rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                pattern TEXT,
                severity INTEGER,
                enabled BOOLEAN
            )""")

            cursor.execute("""CREATE TABLE IF NOT EXISTS whitelist_blacklist (
                entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT CHECK(type IN ('whitelist', 'blacklist')),
                value TEXT,
                comment TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )""")

            cursor.execute("""CREATE TABLE IF NOT EXISTS flows (
                flow_id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER REFERENCES scans(scan_id),
                first_ts TEXT,
                last_ts TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                packet_count INTEGER,
                byte_count INTEGER,
                syn_count INTEGER,
                ack_count INTEGER,
                rst_count INTEGER,
                unique_dst_ports INTEGER,
                meta TEXT
            )""")

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dst_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_flow ON packets(flow_key)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_wb_type_value ON whitelist_blacklist(type, value)")

            self.connection.commit()

    # ---------------- Migrations ----------------
    def _ensure_migrations(self) -> None:
        """
        Adds missing columns to older database versions.
        """
        with self._lock:
            cursor = self.connection.cursor()

            cols = {row[1] for row in cursor.execute("PRAGMA table_info(packets)").fetchall()}
            if "meta" not in cols:
                cursor.execute("ALTER TABLE packets ADD COLUMN meta TEXT")
            if "raw_bytes" not in cols:
                cursor.execute("ALTER TABLE packets ADD COLUMN raw_bytes BLOB")
            if "flow_key" not in cols:
                cursor.execute("ALTER TABLE packets ADD COLUMN flow_key TEXT")

            cols = {row[1] for row in cursor.execute("PRAGMA table_info(alerts)").fetchall()}
            if "pcap_path" not in cols:
                cursor.execute("ALTER TABLE alerts ADD COLUMN pcap_path TEXT")

            cols = {row[1] for row in cursor.execute("PRAGMA table_info(whitelist_blacklist)").fetchall()}
            if "created_at" not in cols:
                cursor.execute("ALTER TABLE whitelist_blacklist ADD COLUMN created_at TEXT")

            self.connection.commit()

    # ---------------- Inserts ----------------
    def insert_packet(self, p: Packet, scan_id: Optional[int] = None) -> int:
        """
        Saves a captured packet in the packets table.
        """
        meta_json = json.dumps(p.meta, ensure_ascii=False) if p.meta else None
        cursor = self._execute(
            """INSERT INTO packets
            (ts, src_ip, dst_ip, src_port, dst_port, proto, proto_name, flags,
                payload_len, raw_len, summary, scan_id, meta, raw_bytes, flow_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                p.ts_iso,
                p.src_ip,
                p.dst_ip,
                p.src_port,
                p.dst_port,
                p.proto,
                p.proto_name,
                p.flags,
                p.payload_len,
                p.raw_len,
                p.summary,
                scan_id,
                meta_json,
                p.raw_bytes,
                p.flow_key,
            ),
        )
        return int(cursor.lastrowid)

    def insert_flow(self, f: FlowStats, scan_id: Optional[int] = None) -> int:
        """
        Saves flow statistics in the flows table.
        """
        meta = {
            "key": list(f.key),
            "dst_ports_seen_sample": list(sorted(f.dst_ports_seen))[:50],
        }
        cursor = self._execute(
            """INSERT INTO flows
            (scan_id, first_ts, last_ts, src_ip, dst_ip, src_port, dst_port, proto,
                packet_count, byte_count, syn_count, ack_count, rst_count, unique_dst_ports, meta)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                f.first_ts.isoformat(timespec="seconds"),
                f.last_ts.isoformat(timespec="seconds"),
                f.src_ip,
                f.dst_ip,
                f.src_port,
                f.dst_port,
                f.proto,
                f.packet_count,
                f.byte_count,
                f.syn_count,
                f.ack_count,
                f.rst_count,
                len(f.dst_ports_seen),
                json.dumps(meta, ensure_ascii=False),
            ),
        )
        return int(cursor.lastrowid)

    def insert_alert(
        self,
        packet_id: Optional[int],
        alert_type: str,
        severity: int,
        description: str,
        timestamp: str,
        pcap_path: Optional[str] = None,
    ) -> int:
        """
        Saves a detected alert in the alerts table.
        """
        cursor = self._execute(
            """INSERT INTO alerts
            (packet_id, alert_type, severity, description, timestamp, pcap_path)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (packet_id, alert_type, severity, description, timestamp, pcap_path),
        )
        return int(cursor.lastrowid)

    def insert_audit(
        self,
        user_email: str,
        action: str,
        params_json: str,
        created_at: str,
        artifact_path: str,
        artifact_sha256: str,
    ) -> int:
        """
        Saves an audit record for a forensic export operation.
        """
        cursor = self._execute(
            """INSERT INTO audit
               (user_email, action, params_json, created_at, artifact_path, artifact_sha256)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                user_email,
                action,
                params_json,
                created_at,
                artifact_path,
                artifact_sha256,
            ),
        )
        return int(cursor.lastrowid)

    def add_list_entry(self, entry_type: str, value: str, comment: str = "") -> int:
        """
        Adds an IP or value to the whitelist or blacklist.
        """
        if entry_type not in ("whitelist", "blacklist"):
            raise ValueError("entry_type must be whitelist or blacklist")

        existing = self._query_one(
            "SELECT entry_id FROM whitelist_blacklist WHERE type = ? AND value = ?",
            (entry_type, value),
        )
        if existing:
            return int(existing["entry_id"])

        cursor = self._execute(
            "INSERT INTO whitelist_blacklist (type, value, comment, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
            (entry_type, value, comment),
        )
        return int(cursor.lastrowid)

    # ---------------- Updates ----------------
    def update_alert_pcap_path(self, alert_id: int, pcap_path: str) -> None:
        """
        Stores the location of an exported PCAP file for a specific alert.
        """
        self._execute(
            "UPDATE alerts SET pcap_path = ? WHERE alert_id = ?",
            (pcap_path, alert_id),
        )

    # ---------------- Queries ----------------
    def get_recent_alerts(self, limit: int = 20):
        """
        Returns the most recent alerts for display in the dashboard.
        """
        rows = self._query_all(
            """SELECT alert_id, alert_type, severity, description,
                    timestamp, pcap_path, packet_id
            FROM alerts
            ORDER BY alert_id DESC
            LIMIT ?""",
            (limit,),
        )
        return [dict(r) for r in rows]

    def get_alert_by_id(self, alert_id: int):
        """
        Retrieves full information about a specific alert.

        Used by the dashboard and forensic export features.
        """
        row = self._query_one(
            """SELECT alert_id, packet_id, alert_type, severity, description, timestamp, pcap_path
               FROM alerts WHERE alert_id = ?""",
            (alert_id,),
        )
        return dict(row) if row else None

    def get_alert_packet_id(self, alert_id: int) -> Optional[int]:
        """
        Returns the packet_id associated with a specific alert.

        Used by the forensic subsystem to locate the packet that triggered
        the alert and reconstruct the relevant evidence.
        """
        row = self._query_one("SELECT packet_id FROM alerts WHERE alert_id = ?", (alert_id,))
        return row["packet_id"] if row else None

    def get_packet_bytes_before(self, packet_id: int, limit: int = 5000) -> list[bytes]:
        """
        Returns raw packet bytes up to a specific packet_id.

        Used by the forensic evidence export process to reconstruct packets
        and generate a PCAP file for further analysis.
        """
        rows = self._query_all(
            """SELECT raw_bytes FROM packets
               WHERE packet_id <= ? AND raw_bytes IS NOT NULL
               ORDER BY packet_id DESC
               LIMIT ?""",
            (packet_id, limit),
        )
        return [r["raw_bytes"] for r in rows if r["raw_bytes"]]

    def get_recent_packets(self, limit: int = 20):
        """
        Returns recently captured packets.
        """
        rows = self._query_all(
            """SELECT packet_id, ts, proto_name, src_ip, dst_ip, src_port, dst_port, raw_len, payload_len, summary
               FROM packets
               ORDER BY packet_id DESC
               LIMIT ?""",
            (limit,),
        )
        return [dict(r) for r in rows]

    def get_protocol_counts(self, minutes: int = 5):
        """
        Counts packets by protocol during the last given number of minutes.
        """
        rows = self._query_all(
            """SELECT COALESCE(proto_name, 'other') AS proto_name, COUNT(*) AS count
               FROM packets
               WHERE datetime(replace(replace(ts, 'T', ' '), 'Z', '')) >= datetime('now', ?)
               GROUP BY COALESCE(proto_name, 'other')
               ORDER BY count DESC""",
            (f"-{int(minutes)} minutes",),
        )
        return {r["proto_name"]: int(r["count"]) for r in rows}

    def get_alert_type_counts(self, minutes: int = 30):
        """
        Counts alerts by alert type during the last given number of minutes.
        """
        rows = self._query_all(
            """SELECT alert_type, COUNT(*) AS count
               FROM alerts
               WHERE datetime(replace(replace(timestamp, 'T', ' '), 'Z', '')) >= datetime('now', ?)
               GROUP BY alert_type
               ORDER BY count DESC, alert_type ASC""",
            (f"-{int(minutes)} minutes",),
        )
        return {r["alert_type"]: int(r["count"]) for r in rows}

    def get_top_talkers(self, minutes: int = 5, limit: int = 10):
        """
        Returns the source IP addresses that sent the most traffic recently.
        """
        rows = self._query_all(
            """SELECT src_ip,
                      COUNT(*) AS packet_count,
                      COALESCE(SUM(raw_len), 0) AS byte_count
               FROM packets
               WHERE datetime(replace(replace(ts, 'T', ' '), 'Z', '')) >= datetime('now', ?)
                 AND src_ip IS NOT NULL AND src_ip != ''
               GROUP BY src_ip
               ORDER BY packet_count DESC, byte_count DESC
               LIMIT ?""",
            (f"-{int(minutes)} minutes", int(limit)),
        )
        return [dict(r) for r in rows]

    def get_packets_per_second(self, seconds: int = 60):
        """
        Returns packet counts grouped by second for dashboard graphing.
        """
        rows = self._query_all(
            """SELECT strftime('%H:%M:%S', datetime(replace(replace(ts, 'T', ' '), 'Z', ''))) AS bucket, COUNT(*) AS count
               FROM packets
               WHERE datetime(replace(replace(ts, 'T', ' '), 'Z', '')) >= datetime('now', ?)
               GROUP BY bucket
               ORDER BY bucket ASC""",
            (f"-{int(seconds)} seconds",),
        )
        return [dict(r) for r in rows]

    def get_dashboard_snapshot(self):
        """
        Returns summary statistics used by the dashboard cards.
        """
        row = self._query_one(
            """SELECT
                (SELECT COUNT(*) FROM packets) AS total_packets,
                (SELECT COUNT(*) FROM alerts) AS total_alerts,
                (SELECT COUNT(*) FROM packets WHERE datetime(replace(replace(ts, 'T', ' '), 'Z', '')) >= datetime('now', '-60 seconds')) AS packets_60s,
                (SELECT COUNT(*) FROM alerts WHERE datetime(replace(replace(timestamp, 'T', ' '), 'Z', '')) >= datetime('now', '-5 minutes')) AS alerts_5m,
                (SELECT COALESCE(SUM(raw_len), 0) FROM packets WHERE datetime(replace(replace(ts, 'T', ' '), 'Z', '')) >= datetime('now', '-60 seconds')) AS bytes_60s,
                (SELECT COUNT(DISTINCT src_ip) FROM packets WHERE src_ip IS NOT NULL AND src_ip != '' AND datetime(replace(replace(ts, 'T', ' '), 'Z', '')) >= datetime('now', '-60 minutes')) AS unique_sources_60m
            """
        )
        return dict(row) if row else {}

    def get_recent_forensics_audit(self, limit: int = 20):
        """
        Returns recent forensic export audit records.
        """
        rows = self._query_all(
            """SELECT audit_id, user_email, action, params_json, created_at, artifact_path, artifact_sha256
               FROM audit
               WHERE action = 'FORENSICS_EXPORT'
               ORDER BY audit_id DESC
               LIMIT ?""",
            (limit,),
        )
        return [dict(r) for r in rows]

    def is_listed(self, entry_type: str, value: str) -> bool:
        """
        Checks whether a value exists in the whitelist or blacklist.
        """
        row = self._query_one(
            "SELECT 1 FROM whitelist_blacklist WHERE type = ? AND value = ? LIMIT 1",
            (entry_type, value),
        )
        return row is not None

    # ---------------- Retention / TTL ----------------
    def delete_old_packets(self, older_than_seconds: int) -> int:
        """
        Deletes packets older than the configured TTL.
        """
        cursor = self._execute(
            f"DELETE FROM packets WHERE {self._sqlite_ts_expr('ts')} < datetime('now', ?)",
            (f"-{int(older_than_seconds)} seconds",),
        )
        return int(cursor.rowcount or 0)

    def delete_old_flows(self, older_than_seconds: int) -> int:
        """
        Deletes flows older than the configured TTL.
        """
        cursor = self._execute(
            f"DELETE FROM flows WHERE {self._sqlite_ts_expr('last_ts')} < datetime('now', ?)",
            (f"-{int(older_than_seconds)} seconds",),
        )
        return int(cursor.rowcount or 0)

    def run_retention_cleanup(self, packet_ttl_seconds: int, flow_ttl_seconds: int) -> dict:
        """
        Runs cleanup for old packets and flows.
        """
        deleted_packets = self.delete_old_packets(packet_ttl_seconds) if packet_ttl_seconds > 0 else 0
        deleted_flows = self.delete_old_flows(flow_ttl_seconds) if flow_ttl_seconds > 0 else 0
        return {
            "deleted_packets": deleted_packets,
            "deleted_flows": deleted_flows,
        }

    def close(self) -> None:
        """
        Closes the database connection.
        """
        with self._lock:
            self.connection.close()
