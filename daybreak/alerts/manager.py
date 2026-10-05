"""Alert manager: cooldown/escalation, rate limiting, persistence, fan-out."""

from __future__ import annotations

import logging
import sqlite3
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Iterable

from ..models import Alert, Severity
from .base import Notifier
from .formatting import human_text

log = logging.getLogger("daybreak.alerts")


@dataclass
class _KeyState:
    last_ts: float
    last_score: int
    last_severity: Severity
    alert_id: int | None
    suppressed: int = 0


# Dedup keys remembered (least recently alerted dropped first).
MAX_DEDUP_KEYS = 8192
# New alert scopes for BSSIDs outside the protected networks (a flood with random BSSIDs makes
# one per BSSID): at most this many per alert type and minute are stored and sent, the rest
# are counted as flood_suppressed. Alerts for protected networks are never held back.
NEW_UNPROTECTED_SCOPES_PER_MINUTE = 6


class TokenBucket:
    """``rate`` notifications per minute, burst of ``rate`` (event-time driven)."""

    def __init__(self, rate: int):
        self.rate = max(0, rate)
        self.tokens = float(self.rate)
        self.last: float | None = None
        self.dropped = 0

    def take(self, now: float) -> bool:
        if self.rate == 0:
            return True  # 0 disables rate limiting
        if self.last is not None:
            self.tokens = min(self.rate, self.tokens + (now - self.last) * self.rate / 60.0)
        self.last = now if self.last is None else max(self.last, now)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        self.dropped += 1
        return False


def _band(severity: Severity) -> int:
    """Rate-limit band: INFO/LOW, MEDIUM, HIGH/CRITICAL."""
    return 0 if severity <= Severity.LOW else (1 if severity == Severity.MEDIUM else 2)


class AlertManager:
    def __init__(self, notifiers: Iterable[Notifier], *, db: Any = None, cooldown: float = 300.0,
                 escalation_delta: int = 10, rate_limit_per_minute: int = 20,
                 human_log: logging.Logger | None = None, dry_run: bool = False):
        self.notifiers = list(notifiers)
        self.db = db
        self.cooldown = cooldown
        self.escalation_delta = escalation_delta
        self.human_log = human_log
        self.dry_run = dry_run
        self.state: OrderedDict[tuple[str, str], _KeyState] = OrderedDict()  # bounded, LRU
        self._new_scopes: dict[str, TokenBucket] = {}
        # One budget per notifier and severity band, so that a flood of low-severity alerts
        # cannot use up the notifications a MEDIUM / HIGH / CRITICAL alert needs.
        self.buckets = {(id(n), band): TokenBucket(rate_limit_per_minute)
                        for n in self.notifiers if n.rate_limited for band in (0, 1, 2)}
        self.stats = {"submitted": 0, "delivered": 0, "suppressed": 0, "rate_limited": 0, "notifier_errors": 0,
                      "flood_suppressed": 0, "storage_errors": 0}
        self.delivered: list[Alert] = []

    def submit(self, alert: Alert) -> bool:
        """Returns True if the alert was delivered, False if suppressed by cooldown."""
        self.stats["submitted"] += 1
        key = alert.dedup_key
        st = self.state.get(key)
        if st is None and alert.network is None and alert.bssid:
            bucket = self._new_scopes.get(alert.alert_type)
            if bucket is None:
                bucket = self._new_scopes[alert.alert_type] = TokenBucket(NEW_UNPROTECTED_SCOPES_PER_MINUTE)
            if not bucket.take(alert.timestamp):
                self.stats["flood_suppressed"] += 1
                return False
        if st is not None and alert.timestamp - st.last_ts < self.cooldown:
            escalated = (alert.score >= st.last_score + self.escalation_delta
                         or alert.severity > st.last_severity)
            if not escalated:
                st.suppressed += 1
                self.stats["suppressed"] += 1
                if self.db is not None and st.alert_id is not None and not self.dry_run:
                    self._db_write(self.db.note_suppressed, st.alert_id, alert.timestamp)
                return False
        alert.suppressed_count = st.suppressed if st is not None else 0
        if self.db is not None and not self.dry_run:
            self._db_write(self.db.insert_alert, alert)  # a failed write still notifies
        self.state[key] = _KeyState(alert.timestamp, alert.score, alert.severity, alert.id)
        self.state.move_to_end(key)
        if len(self.state) > MAX_DEDUP_KEYS:
            self.state.popitem(last=False)
        self.stats["delivered"] += 1
        self.delivered.append(alert)
        if len(self.delivered) > 5000:
            del self.delivered[:-2500]
        if self.human_log is not None and not self.dry_run:
            self.human_log.info(human_text(alert) + "\n")
        self._fan_out(alert)
        return True

    def _db_write(self, fn: Any, *args: Any) -> None:
        try:
            fn(*args)
        except (sqlite3.Error, ValueError) as exc:  # disk full, locked, bad content: keep detecting
            self.stats["storage_errors"] += 1
            log.warning("alert database write failed: %s", exc)

    def _fan_out(self, alert: Alert) -> None:
        for n in self.notifiers:
            if not n.accepts(alert):
                continue
            note = None
            bucket = self.buckets.get((id(n), _band(alert.severity)))
            if bucket is not None:
                dropped_before = bucket.dropped
                if not bucket.take(alert.timestamp):
                    self.stats["rate_limited"] += 1
                    continue
                if dropped_before:
                    note = f"{dropped_before} notification(s) skipped by rate limit"
                    bucket.dropped = 0
            try:
                n.notify(alert, note=note)
            except Exception as exc:  # a broken notifier must never stop detection
                n.errors += 1
                n.last_error = str(exc)
                self.stats["notifier_errors"] += 1
                log.warning("notifier %s failed: %s", n.type_name, exc)

    def close(self) -> None:
        for n in self.notifiers:
            try:
                n.close()
            except Exception:
                pass
