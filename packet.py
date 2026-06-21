"""
מחלקת Packet מייצגת חבילת רשת בודדת לאחר נרמול (Normalization).

המחלקה מרכזת את כל המידע הרלוונטי מתוך חבילת הרשת,
כגון כתובות IP, פורטים, פרוטוקול, גודל החבילה ודגלי TCP.

שאר רכיבי המערכת עובדים מול אובייקטי Packet במקום לעבוד ישירות מול חבילות Scapy.
"""

#from __future__ import annotations  # מאפשרת להשתמש ברמזי טיפוסים (Type Hints) בצורה גמישה יותר, גם כאשר המחלקות עדיין לא נוצרו בזמן פירוש הקוד.

from datetime import datetime  # time of sniffing a packet
from typing import Optional, Union  # Optional = value may be None. Union = value may have multiple possible types.


class Packet:
    """
    Represents a normalized network packet.

    Stores packet metadata in a unified format used by
    the detection, database and flow analysis modules.
    """
    def __init__(
        self,
        ts: datetime,
        raw_len: int,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int],
        dst_port: Optional[int],
        proto: Optional[int],
        flags: Optional[Union[str, int]],   # flags can be strings, numbers or None
        payload_len: int = 0,
        summary: str = "",
        meta: dict | None = None,
        raw_bytes: bytes | None = None,
        flow_key: str | None = None,
    ):
        # Packet timestamp
        self.ts = ts.replace(tzinfo=None) if ts.tzinfo else ts
        # Timestamp formatted for JSON/database storage
        self.ts_iso = self.ts.isoformat(timespec="milliseconds") + "Z"
        # Total packet size in bytes
        self.raw_len = raw_len
        # Source and destination IP addresses
        self.src_ip, self.dst_ip = src_ip, dst_ip
        # Source and destination transport-layer ports
        self.src_port, self.dst_port = src_port, dst_port
        # Protocol number (6=TCP, 17=UDP, 1=ICMP)
        self.proto = proto
        # Human-readable protocol name
        self.proto_name = {6: "tcp", 17: "udp", 1: "icmp"}.get(proto, "other")
        # TCP flags such as SYN, ACK, RST
        self.flags = None if flags is None else str(flags)
        # Payload size excluding protocol headers
        self.payload_len = payload_len
        # Short textual summary of the packet
        self.summary = summary or self.summary_text()
        # Additional protocol-specific information
        self.meta = meta or {}
        # Original packet bytes (if stored)
        self.raw_bytes = raw_bytes
        # Identifier of the flow this packet belongs to
        self.flow_key = flow_key

    def summary_text(self) -> str:
        """
        Generates a human-readable summary of the packet.
        Return example: TCP 192.168.1.5:1234 -> 8.8.8.8:80
        """
        left = self.src_ip or "?"
        right = self.dst_ip or "?"
        lport = f":{self.src_port}" if self.src_port is not None else ""
        rport = f":{self.dst_port}" if self.dst_port is not None else ""
        return f"{self.proto_name.upper()} {left}{lport} -> {right}{rport}"

    def to_dict(self) -> dict:
        """
        Converts the packet into a dictionary for
        logging, storage and JSON serialization.
        """
        return {
            "ts": self.ts_iso,
            "raw_len": self.raw_len,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "proto_name": self.proto_name,
            "flags": self.flags,
            "payload_len": self.payload_len,
            "summary": self.summary,
            "meta": self.meta,
            "flow_key": self.flow_key,
            "has_raw": self.raw_bytes is not None,
        }
