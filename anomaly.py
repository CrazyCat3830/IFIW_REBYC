"""
קובץ זה אחראי על זיהוי אנומליות בתעבורת הרשת.

המערכת בונה קו בסיס (Baseline) של כמות החבילות בשנייה לאורך זמן,
ומשווה אליו את קצב התעבורה הנוכחי.

כאשר קצב התעבורה הנוכחי גבוה משמעותית מהתנהגות הרשת הרגילה,
נוצרת התראת ANOMALY_TRAFFIC.
"""
from __future__ import annotations

from collections import deque  # Double-ended queue. Efficiently adds/removes elements from both ends.
from datetime import datetime  # Used for packet timestamps and time based calculations.
from typing import Deque, Dict, Optional, Tuple  # Type hints used for readability and IDE support.

from packet import Packet


class RollingCountPerSecond:
    """
    Maintains packet counts per second inside a sliding time window.
    """

    def __init__(self, window_seconds: int):
        self.window_seconds = int(window_seconds)
        self.buckets: Deque[Tuple[int, int]] = deque()  # (epoch_second, count)

    def add_packet(self, ts: datetime) -> None:
        sec = int(ts.timestamp())  # Convert datetime into Unix timestamp (seconds since 1/1/1970)
        if self.buckets and self.buckets[-1][0] == sec:
            s, c = self.buckets[-1]
            self.buckets[-1] = (s, c + 1)
        else:
            self.buckets.append((sec, 1))  # Create a new bucket for a new second
        self._purge(sec)

    def _purge(self, now_sec: int) -> None:
        # Remove buckets that are outside the sliding window
        cutoff = now_sec - self.window_seconds
        while self.buckets and self.buckets[0][0] < cutoff:
            self.buckets.popleft()

    def mean_std(self) -> Tuple[float, float]:
        # Calculate mean and standard deviation of packet counts
        if not self.buckets:
            return 0.0, 0.0
        vals = [c for _, c in self.buckets]
        n = len(vals)
        mean = sum(vals) / n  # ממוצע
        var = sum((x - mean) ** 2 for x in vals) / n  # שונות
        return mean, var ** 0.5  # סטיית תקן, ממוצע

    def current_pps(self, last_seconds: int = 1) -> float:
        # Calculate current packets-per-second value over the requested interval
        if not self.buckets:
            return 0.0
        last_seconds = max(1, int(last_seconds))
        now_sec = self.buckets[-1][0]
        cutoff = now_sec - last_seconds + 1
        total = sum(c for s, c in self.buckets if s >= cutoff)
        return total / last_seconds


# Global anomaly state
_state: Dict[str, dict] = {}

# Number of seconds used to build normal traffic baseline
BASELINE_WINDOW_SECONDS = 60
# Number of seconds used to calculate current traffic rate
CURRENT_WINDOW_SECONDS = 5
# Number of standard deviations required to trigger anomaly
Z_THRESHOLD = 3.0
# Ignore low traffic volumes to reduce false positives
MIN_CURRENT_PPS = 300.0

# Required traffic multiplier when baseline variance is near zero
ZERO_STD_MULTIPLIER = 4.0
# Minimum PPS increase required when baseline variance is near zero
ZERO_STD_MIN_ABSOLUTE_JUMP = 500.0


def update_and_check_anomaly(p: Packet, key: str = "global") -> Optional[dict]:
    """
    Updates traffic statistics and checks whether
    current traffic significantly deviates from baseline.

    - Builds a baseline over 60s of per-second packet counts.
    - Checks current PPS over 5s against baseline using z-score.
    """
    # Only count real network packets (ignore None ts)
    if not isinstance(p.ts, datetime):
        return None

    st = _state.get(key)
    if st is None:
        st = {
            "baseline": RollingCountPerSecond(BASELINE_WINDOW_SECONDS),
            "current": RollingCountPerSecond(CURRENT_WINDOW_SECONDS),
            "warmup_started": p.ts,
        }
        _state[key] = st

    st["baseline"].add_packet(p.ts)
    st["current"].add_packet(p.ts)

    # Warmup: wait until we have enough baseline data (at least ~10 buckets)
    if len(st["baseline"].buckets) < 10:
        return None

    mean, std = st["baseline"].mean_std()
    cur = st["current"].current_pps(last_seconds=CURRENT_WINDOW_SECONDS)

    if cur < MIN_CURRENT_PPS:
        return None

    if std <= 0.00001:
        # If traffic was almost constant, treat big jumps as anomaly
        if cur > max(mean * ZERO_STD_MULTIPLIER, mean + ZERO_STD_MIN_ABSOLUTE_JUMP):  # fallback thresholds for near-zero variance
            # בסטיית תקן קטנה כל קפיצה נראית אנומליה. לכן נבדוק אם יש פי 4 פאקטות מהממוצע
            # או לפחות 500 יותר, למקרה שהתעבורה נמוכה.
            # זה מונע false positive
            return {
                "type": "ANOMALY_TRAFFIC",
                "severity": 6,
                "description": f"Traffic anomaly: current ~{cur:.0f} PPS vs baseline mean ~{mean:.0f} PPS",
                "evidence_key": p.src_ip or p.dst_ip or "global",
            }
        return None
    # Z-score: measures how far current traffic deviates from normal behaviour
    z = (cur - mean) / std
    if z >= Z_THRESHOLD:
        return {
            "type": "ANOMALY_TRAFFIC",
            "severity": 6,
            "description": (
                f"Traffic anomaly (z={z:.1f}): current ~{cur:.0f} PPS, baseline mean ~{mean:.0f}±{std:.0f} PPS"
            ),
            "evidence_key": p.src_ip or p.dst_ip or "global",
        }

    return None
