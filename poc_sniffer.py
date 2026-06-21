"""
קובץ זה אחראי על נרמול (Normalization) של חבילות רשת שנקלטו באמצעות Scapy.

הקובץ מחלץ מתוך החבילה מידע רלוונטי כגון כתובות IP, פורטים,
פרוטוקולים, מידע על DNS, DHCP, ARP ו-WiFi.

בסיום התהליך נוצר אובייקט Packet אחיד שבו משתמשים
שאר רכיבי המערכת לצורך ניתוח, זיהוי מתקפות ושמירה במסד הנתונים.
"""
from __future__ import annotations

from datetime import datetime, timezone

from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.dot11 import (  # 802.11 - WiFi protocol packets
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeResp,
    RadioTap,
)
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from flows import compute_flow_key
from packet import Packet


def _safe_decode(v):
    """
    Safely converts bytes to string while ignoring decoding errors.
    """
    if v is None:
        return None
    if isinstance(v, bytes):
        return v.decode(errors="ignore")
    return str(v)


def _extract_wifi_meta(pkt, meta: dict) -> None:
    """
    Extracts WiFi-specific metadata from 802.11 packets.
    """
    if pkt.haslayer(Dot11):  # Scapy helper that checks whether the packet contains an 802.11 (WiFi) layer
        d11 = pkt[Dot11]  # Access the Dot11 layer directly from the Scapy packet
        # Safely read a field from the packet. Returns None if the field does not exist.
        meta["l2_src"] = getattr(d11, "addr2", None)
        meta["l2_dst"] = getattr(d11, "addr1", None)
        meta["wifi_bssid"] = getattr(d11, "addr3", None)

        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            meta["wifi_is_beacon"] = True
        else:
            meta["wifi_is_beacon"] = False

        elt = pkt.getlayer(Dot11Elt)  # Retrieves the first 802.11 information element (SSID, channel, etc.)
        while elt is not None:  # Iterate through all WiFi information elements carried in the frame
            try:
                if getattr(elt, "ID", None) == 0:
                    meta["wifi_ssid"] = _safe_decode(getattr(elt, "info", b""))  # שם רשת
                elif getattr(elt, "ID", None) == 3:
                    info = getattr(elt, "info", b"")
                    if info:
                        meta["wifi_channel"] = int(info[0]) if isinstance(info, (bytes, bytearray)) else int(info) # ערוץ
            except Exception:
                pass
            elt = getattr(elt, "payload", None)
            if not isinstance(elt, Dot11Elt):
                break

    if pkt.haslayer(RadioTap):
        rt = pkt[RadioTap]
        for attr in ("dBm_AntSignal", "dBm_AntNoise"):
            val = getattr(rt, attr, None)
            if val is not None and attr == "dBm_AntSignal":
                try:
                    meta["wifi_rssi_dbm"] = int(val)  # עוצמת קליטה
                except Exception:
                    pass

        channel = getattr(rt, "ChannelFrequency", None)
        if channel and "wifi_channel" not in meta:
            freq_to_channel = {
                2412: 1, 2417: 2, 2422: 3, 2427: 4, 2432: 5, 2437: 6, 2442: 7,
                2447: 8, 2452: 9, 2457: 10, 2462: 11, 2467: 12, 2472: 13, 2484: 14,
                5180: 36, 5200: 40, 5220: 44, 5240: 48, 5745: 149, 5765: 153,
                5785: 157, 5805: 161, 5825: 165,
            }
            meta["wifi_channel"] = freq_to_channel.get(int(channel), int(channel))


def normalize_packet(pkt) -> Packet:
    """
    Converts a Scapy packet into a normalized Packet object
    used throughout the system.
    """
    # Convert the entire Scapy packet into raw bytes for forensic storage
    raw_bytes = bytes(pkt)
    # Convert Scapy timestamp into a timezone-aware UTC datetime object
    ts = datetime.fromtimestamp(getattr(pkt, "time", datetime.now().timestamp()), tz=timezone.utc)

    src = dst = None
    sport = dport = None
    proto = None
    flags = None
    payload_len = 0
    summary = pkt.summary()
    meta = {}

    _extract_wifi_meta(pkt, meta)

    if pkt.haslayer(DNS):
        d = pkt[DNS]
        # DNS qr flag: 0=query, 1=response
        if getattr(d, "qr", 0) == 1:
            try:
                if d.qd and isinstance(d.qd, DNSQR) and d.qd.qname:
                    q = d.qd.qname.decode(errors="ignore")
                    meta["dns_qname"] = q.rstrip(".")  # Remove the trailing dot commonly found in DNS names
            except Exception:
                pass

            answers = []
            try:
                an = d.an
                # Iterate over all DNS answer records reported by the DNS packet
                for _ in range(int(getattr(d, "ancount", 0) or 0)):
                    if isinstance(an, DNSRR):
                        answers.append(str(an.rdata))
                    an = getattr(an, "payload", None)
            except Exception:
                pass
            if answers:
                meta["dns_answers"] = answers

    if pkt.haslayer(DHCP):
        dhcp = pkt[DHCP]
        for opt in getattr(dhcp, "options", []):
            if isinstance(opt, tuple):
                key, val = opt[0], opt[1]
                if key == "message-type":
                    meta["dhcp_type"] = str(val).lower()
                elif key == "server_id":
                    meta["dhcp_server_id"] = str(val)

    if pkt.haslayer(ARP):
        a = pkt[ARP]
        meta["arp_ip"] = a.psrc
        meta["arp_mac"] = a.hwsrc
        # Only set the value if it was not already extracted earlier
        meta.setdefault("l2_src", a.hwsrc)
        meta.setdefault("l2_dst", a.hwdst)

    if pkt.haslayer(IP):
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        proto = ip.proto  # IP protocol number (e.g. 6=TCP, 17=UDP, 1=ICMP)
        # Calculate payload size by converting the payload layer to raw bytes
        payload_len = len(bytes(ip.payload)) if getattr(ip, "payload", None) else 0
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        src, dst = ip.src, ip.dst
        proto = ip.nh
        payload_len = len(bytes(ip.payload)) if getattr(ip, "payload", None) else 0

    if pkt.haslayer(TCP):
        t = pkt[TCP]
        sport, dport = int(t.sport), int(t.dport)
        flags = str(t.flags)
        proto = 6
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        sport, dport = int(u.sport), int(u.dport)
        proto = 17
    elif pkt.haslayer(ICMP):
        proto = 1

    p = Packet(
        ts=ts,
        raw_len=len(raw_bytes),
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        proto=proto,
        flags=flags,
        payload_len=payload_len,
        summary=summary,
        meta=meta,
        raw_bytes=raw_bytes,
        flow_key=None,
    )
    # Generate a unique identifier that groups packets belonging to the same flow
    p.flow_key = str(compute_flow_key(p))
    return p
