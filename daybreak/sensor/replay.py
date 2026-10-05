"""Replay backend: feeds a JSONL stream of synthetic/recorded *metadata* events.

Used for tests, demos and forensic re-analysis without touching the radio.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import IO, Iterable

from ..models import Event, MalformedEventError
from .backend import Backend, BackendStatus


class ReplayBackend(Backend):
    name = "replay"

    def __init__(self, source: str | Path | Iterable[str], *, sensor_name: str = "replay",
                 realtime: bool = False, speed: float = 1.0, batch: int = 500):
        super().__init__(sensor_name)
        self.source = source
        self.realtime = realtime
        self.speed = max(speed, 1e-6)
        self.batch = batch
        self._fh: IO[str] | None = None
        self._lines: Iterable[str] | None = None
        self._iter = None
        self._done = False
        self._line_no = 0
        self._first_event_ts: float | None = None
        self._wall_start: float | None = None
        self._pending: Event | None = None

    def open(self) -> None:
        if isinstance(self.source, (str, Path)):
            self._fh = open(self.source, encoding="utf-8")
            self._iter = iter(self._fh)
        else:
            self._iter = iter(self.source)

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    @property
    def finished(self) -> bool:
        return self._done and self._pending is None

    def _next_event(self) -> Event | None:
        assert self._iter is not None, "open() first"
        for line in self._iter:
            self._line_no += 1
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            try:
                ev = Event.from_json(text, default_sensor=self.sensor_name)
            except (MalformedEventError, ValueError, TypeError, OverflowError, RecursionError) as exc:
                self.stats["malformed"] += 1
                self.note_error(f"line {self._line_no}: {exc}")
                continue
            self.stats["events"] += 1
            return ev
        self._done = True
        return None

    def poll(self, timeout: float) -> list[Event]:
        out: list[Event] = []
        deadline = time.monotonic() + max(timeout, 0)
        while len(out) < self.batch:
            ev = self._pending or self._next_event()
            self._pending = None
            if ev is None:
                break
            if self.realtime:
                if self._first_event_ts is None:
                    self._first_event_ts, self._wall_start = ev.timestamp, time.monotonic()
                due = self._wall_start + (ev.timestamp - self._first_event_ts) / self.speed
                now = time.monotonic()
                if due > now:
                    if due > deadline:
                        self._pending = ev
                        if not out:
                            time.sleep(max(0.0, deadline - now))
                        break
                    time.sleep(due - now)
            out.append(ev)
        return out

    def status(self) -> BackendStatus:
        src = self.source if isinstance(self.source, (str, Path)) else "stream"
        if not (self.stats["events"] or self.stats["malformed"]):
            return BackendStatus(self.name, True, f"replaying {src}")
        return BackendStatus(self.name, True, f"replaying {src} ({self.stats['events']} events, "
                             f"{self.stats['malformed']} malformed)")
