"""
קובץ זה מגדיר מערכת הודעות פנימית בין רכיבי המערכת.

ה-Orchestrator משתמש ב-MessageBus כדי לפרסם הודעות על אירועים,
כגון התחלת ניטור, עצירת ניטור, זיהוי התראה או פעולה שננקטה.

ההודעות נשמרות בתור זמני, וה-Dashboard יכול לקרוא אותן ולהציג אותן למשתמש.
"""
from __future__ import annotations

from collections import deque  # Queue-like structure with a maximum length
from dataclasses import dataclass  # Automatically creates simple data classes
from datetime import datetime
from threading import Lock  # Prevents multiple threads from modifying the queue at the same time
from typing import Deque, Optional


@dataclass
class Message:
    ts: str
    level: str
    title: str
    body: str = ""
    alert_id: Optional[int] = None


class MessageBus:
    """Thread-safe in-process message system for UI/logging."""

    def __init__(self, maxlen: int = 200):
        self._q: Deque[Message] = deque(maxlen=maxlen)
        self._lock = Lock()

    def publish(self, level: str, title: str, body: str = "", alert_id: Optional[int] = None) -> None:
        """
        Adds a new message to the message queue.
        Used by the Orchestrator to report events to the UI.
        """
        ts = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        # Prevent race conditions between UI and background threads
        with self._lock:
            self._q.append(Message(ts=ts, level=level, title=title, body=body, alert_id=alert_id))

    def consume_all(self) -> list[Message]:
        """
        Returns all pending messages and clears the queue.
        Used by the UI to display new system messages.
        """
        # Lock the queue to prevent simultaneous access from multiple threads
        with self._lock:
            msgs = list(self._q)
            self._q.clear()
        return msgs
