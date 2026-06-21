"""
קובץ זה אחראי על קבלת החלטות תגובה להתראות שזוהו במערכת.

לאחר זיהוי מתקפה, המערכת ממפה את סוג ההתראה ורמת החומרה
לפעולת תגובה מומלצת כגון חסימה זמנית, הגבלת קצב תעבורה
או הצגת התראה למשתמש.

בגרסה זו הפעולות הן המלצות בלבד ואינן מבוצעות אוטומטית.
"""
from __future__ import annotations

from dataclasses import dataclass  # Automatically generates a simple data container class
from typing import Optional  # Indicates that a field may also contain None


@dataclass
class PolicyResult:
    """
    Represents the response policy selected for a detected alert.
    """
    action: str  # Recommended action: NONE/BLOCK/RATE_LIMIT/NOTIFY
    target: Optional[str] = None
    ttl_seconds: Optional[int] = None
    reason: str = ""


def decide_policy(alert_type: str, severity: int) -> PolicyResult:
    """Map alerts to a basic prevention policy.

    NOTE: We keep this safe: no automatic iptables by default.
    """
    # Convert alert type to uppercase and safely handle None values
    alert_type = (alert_type or "").upper()

    if alert_type == "PORT_SCAN" and severity >= 7:
        return PolicyResult(action="BLOCK", ttl_seconds=60, reason="Temporary block for port scanning")

    if alert_type == "SYN_FLOOD" and severity >= 8:
        return PolicyResult(action="RATE_LIMIT", ttl_seconds=120, reason="Rate limit traffic to mitigate SYN flood")

    if alert_type == "ARP_SPOOF" and severity >= 8:
        return PolicyResult(action="NOTIFY", reason="ARP spoof suspected — recommend isolating device / static ARP")

    if alert_type.startswith("ANOMALY"):
        return PolicyResult(action="NOTIFY", reason="Traffic anomaly detected — investigate")
        
    if alert_type == "DNS_POISON" and severity >= 8:
        return PolicyResult(action="NOTIFY", reason="DNS poisoning suspected — check resolver / isolate rogue DNS")

    if alert_type == "DHCP_SPOOF" and severity >= 8:
        return PolicyResult(action="NOTIFY", reason="DHCP spoof suspected — check for rogue DHCP server")

    return PolicyResult(action="NONE")
