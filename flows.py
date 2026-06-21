"""
קובץ זה אחראי על ניהול וסטטיסטיקות של Flows ברשת.

הFlow מייצג תקשורת בין שני קצוות ברשת (IP, פורטים ופרוטוקול).
הקובץ יוצר מזהה ייחודי לכל Flow ושומר נתונים סטטיסטיים כגון:
מספר חבילות, נפח תעבורה ודגלי TCP.

המידע משמש לזיהוי מתקפות, אנומליות וניתוח תעבורת רשת.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime  # used for first_ts, last_ts
from typing import Optional, Tuple

from packet import Packet


FlowKey = Tuple[str, str, int, int, str]  # (src_ip, dst_ip, src_port, dst_port, protocol)


def compute_flow_key(p: Packet) -> Optional[FlowKey]:
    """Compute a bidirectional flow key.

    For TCP/UDP we normalize endpoint order so A->B and B->A share the same
    flow. For protocols without ports we use 0/0.
    """
    if not p.src_ip or not p.dst_ip:
        return None

    proto = p.proto_name or "other"
    src_port = int(p.src_port or 0)
    dst_port = int(p.dst_port or 0)
    # Build endpoint tuples for comparison and normalization
    left = (str(p.src_ip), src_port)
    right = (str(p.dst_ip), dst_port)
    # Sort endpoints so both traffic directions share the same flow key
    if left <= right:
        return (left[0], right[0], left[1], right[1], proto)
    return (right[0], left[0], right[1], left[1], proto)


@dataclass
class FlowStats:
    key: FlowKey
    first_ts: datetime  # Timestamp of the first packet in the flow
    last_ts: datetime  # Timestamp of the most recent packet in the flow

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str

    packet_count: int = 0  # Total packets observed in this flow
    byte_count: int = 0  # Total traffic volume in bytes

    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    # Unique destination ports contacted during this flow
    dst_ports_seen: set[int] = field(default_factory=set)

    @classmethod  # Factory method that creates a new FlowStats object from the first packet
    def from_packet(cls, key: FlowKey, p: Packet) -> "FlowStats":
        return cls(
            key=key,
            first_ts=p.ts,
            last_ts=p.ts,
            src_ip=key[0],
            dst_ip=key[1],
            src_port=key[2],
            dst_port=key[3],
            proto=key[4],
            packet_count=0,
            byte_count=0,
        )

    def update(self, p: Packet) -> None:
        """
        Updates flow statistics using a newly captured packet.
        """
        self.last_ts = p.ts
        self.packet_count += 1
        self.byte_count += int(p.raw_len or 0)  # Add packet size to the total traffic volume

        if p.dst_port is not None:
            try:
                self.dst_ports_seen.add(int(p.dst_port))  # Track unique destination ports for scan detection
            except Exception:
                pass

        if self.proto == "tcp" and isinstance(p.flags, str):
            flags = p.flags
            if "S" in flags and "A" not in flags:  # Count pure SYN packets (used for SYN flood detection)
                self.syn_count += 1
            if "A" in flags:  # Count ACK packets
                self.ack_count += 1
            if "R" in flags:  # Count TCP reset packets
                self.rst_count += 1
