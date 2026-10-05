"""Event pipeline: dedup -> scope -> store -> detect -> correlate -> alert sink."""

from __future__ import annotations

import logging
import sqlite3
import time
from collections import Counter, OrderedDict
from typing import Any, Callable

from .baseline.engine import BaselineDetector
from .config import Config
from .correlation.engine import CorrelationEngine
from .detectors.base import SENSOR_LOST, SENSOR_RECOVERED, DetectionContext
from .detectors.deauth import DeauthDetector
from .detectors.eapol import EapolDetector
from .detectors.kismet_alerts import KismetAlertDetector
from .detectors.spoof import SpoofDetector
from .models import (
    AP_OBSERVATION_TYPES, CONNECT_TYPES, DISCONNECT_TYPES, Alert, Event, EventType, ScoreComponent,
)
from .registry import NetworkRegistry


class StorageBudget:
    """Token bucket per key (event time): during a flood only a sample is written to the
    database. Detection still sees every event; the skipped ones are counted."""

    def __init__(self, rate: float, burst: float, max_keys: int = 4096):
        self.rate = rate
        self.burst = burst
        self.max_keys = max_keys
        self._buckets: OrderedDict[Any, list[float]] = OrderedDict()

    def allow(self, key: Any, now: float) -> bool:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = self._buckets[key] = [self.burst, now]
            if len(self._buckets) > self.max_keys:
                self._buckets.popitem(last=False)
        else:
            self._buckets.move_to_end(key)
            bucket[0] = min(self.burst, bucket[0] + max(0.0, now - bucket[1]) * self.rate)
            bucket[1] = max(bucket[1], now)
        if bucket[0] >= 1.0:
            bucket[0] -= 1.0
            return True
        return False


# Stored per (event type, BSSID): a burst of 500, then 50 per second; and for unregistered BSSIDs
# also a burst of 1000, then 100 per second over all of them (a flood from random BSSIDs would
# otherwise get a fresh burst for every BSSID).
EVENT_STORAGE_RATE, EVENT_STORAGE_BURST = 50.0, 500.0
EVENT_STORAGE_TOTAL_RATE, EVENT_STORAGE_TOTAL_BURST = 100.0, 1000.0
# New database rows for unregistered BSSIDs: 256 per SSID and hour, and for SSIDs that are not
# protected also 1024 per hour over all of them (with detection.scope "all", a flood of random
# SSIDs would otherwise get 256 each, and must not crowd out a rogue BSSID of a protected SSID).
UNKNOWN_AP_ROWS_PER_HOUR = 256
UNKNOWN_AP_ROWS_TOTAL_PER_HOUR = 1024
# New station rows (a flood of random client MACs would add one per MAC): 1024 per hour for each
# registered BSSID, and 1024 per hour for all other BSSIDs together.
NEW_STATION_ROWS_PER_HOUR = 1024
MAX_STATION_WRITE_KEYS = 8192
MAX_AP_WRITE_KEYS = 8192


class Deduplicator:
    """Drops exact duplicates and 802.11 retransmissions (retry bit + same sequence)."""

    def __init__(self, window: float = 2.0, retry_window: float = 0.5, max_entries: int = 100_000):
        self.window = window
        self.retry_window = retry_window
        self.max_entries = max_entries
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._seq: OrderedDict[tuple, float] = OrderedDict()

    def _trim(self, book: OrderedDict, now: float, window: float) -> None:
        while book and (len(book) > self.max_entries or now - next(iter(book.values())) > window):
            book.popitem(last=False)

    def is_duplicate(self, ev: Event) -> bool:
        now = ev.timestamp
        fp = ev.fingerprint()
        if fp in self._seen and now - self._seen[fp] <= self.window:
            return True
        self._seen[fp] = now
        self._seen.move_to_end(fp)
        self._trim(self._seen, now, self.window)
        seq = ev.metadata.get("seq")
        if seq is not None and ev.source:
            key = (ev.event_type.value, ev.source, ev.destination, seq)
            prev = self._seq.get(key)
            self._seq[key] = now
            self._seq.move_to_end(key)
            self._trim(self._seq, now, self.retry_window)
            if ev.metadata.get("retry") and prev is not None and now - prev <= self.retry_window:
                return True
        return False


def sensor_alert(status: str, ts: float, *, sensor: str, interface: str | None,
                 details: dict[str, Any] | None = None, weight: int = 50) -> Alert:
    details = dict(details or {})
    if status == SENSOR_LOST:
        comps = [ScoreComponent(weight, "sensor lost", f"{interface} disappeared", "sensor_lost")]
        summary = (f"Sensor {interface} is gone (USB unplug, driver reset or firmware crash). "
                   "Monitoring is paused until it returns.")
        score = weight
    else:
        comps = [ScoreComponent(0, "sensor recovered", f"{interface} is back", "sensor_recovered")]
        summary = f"Sensor {interface} recovered; passive monitoring resumed."
        score = 0
    details.setdefault("interface", interface)
    return Alert(status, ts, score, comps, summary=summary, sensor=sensor, details=details)


PROTECTED_INTERFACE_CHANGED = "PROTECTED_INTERFACE_CHANGED"


def protected_alert(ts: float, changes: dict[str, list[str]], *, sensor: str, weight: int = 50) -> Alert:
    """A protected interface (the internet link) changed state during a live run."""
    detail = "; ".join(f"{name}: {', '.join(diff)}" for name, diff in sorted(changes.items()))
    comps = [ScoreComponent(weight, "protected interface changed", detail, "protected_interface_changed")]
    summary = ("A protected interface changed state while monitoring. daybreak-wids sends no commands to "
               "protected interfaces; automatic sensor re-preparation is disabled for this run.")
    return Alert(PROTECTED_INTERFACE_CHANGED, ts, weight, comps, summary=summary, sensor=sensor,
                 details={"changes": changes})


class Pipeline:
    def __init__(self, config: Config, *, db: Any = None, sink: Callable[[Alert], Any] | None = None,
                 baseline: Any = None, extra_detectors: list[Any] | None = None):
        self.config = config
        self.db = db
        self.sink = sink
        self.registry = NetworkRegistry(config.protected_networks, scope=config.detection.scope)
        self.ctx = DetectionContext(config, self.registry, baseline=baseline)
        self.detectors: list[Any] = [
            DeauthDetector(config.detection.deauth),
            EapolDetector(config.detection.eapol),
            SpoofDetector(config.detection.spoof),
            KismetAlertDetector(),
            BaselineDetector(config.detection.baseline),
        ]
        self.detectors += list(extra_detectors or [])
        self.correlator = CorrelationEngine(config, self.ctx)
        self.dedup = Deduplicator()
        self.stats: Counter[str] = Counter()
        self.alerts: list[Alert] = []
        self.network_ids: dict[str, int] = db.sync_networks(config.protected_networks) if db else {}
        self._events: list[Event] = []
        self._stations: Counter[tuple[str, str, str]] = Counter()
        self._station_seen: dict[tuple[str, str], float] = {}
        self._ap_written: OrderedDict[tuple[str, str], tuple[float, Any, int | None]] = OrderedDict()
        self._event_budget = StorageBudget(EVENT_STORAGE_RATE, EVENT_STORAGE_BURST)
        self._event_total = StorageBudget(EVENT_STORAGE_TOTAL_RATE, EVENT_STORAGE_TOTAL_BURST)
        self._station_budget = StorageBudget(NEW_STATION_ROWS_PER_HOUR / 3600.0, NEW_STATION_ROWS_PER_HOUR)
        self._station_written: OrderedDict[tuple[str, str], None] = OrderedDict()
        self._unknown_ap_budget = StorageBudget(UNKNOWN_AP_ROWS_PER_HOUR / 3600.0, UNKNOWN_AP_ROWS_PER_HOUR)
        self._unknown_ap_total = StorageBudget(UNKNOWN_AP_ROWS_TOTAL_PER_HOUR / 3600.0, UNKNOWN_AP_ROWS_TOTAL_PER_HOUR)
        self._last_flush = time.monotonic()
        self._last_expire: float | None = None
        self.last_event_ts: float | None = None
        self.last_error: str | None = None
        self.type_counts: Counter[str] = Counter()
        # Callables receiving every de-duplicated, in-scope event (e.g. baseline learning).
        self.observers: list[Callable[[Event], Any]] = []

    def add_detector(self, detector: Any) -> None:
        self.detectors.append(detector)

    # -- main entry ----------------------------------------------------------------
    def process(self, ev: Event) -> list[Alert]:
        self.stats["received"] += 1
        if self.dedup.is_duplicate(ev):
            self.stats["duplicates"] += 1
            return []
        if not self.registry.in_scope(ev):
            self.stats["out_of_scope"] += 1
            return []
        self.stats["processed"] += 1
        self.type_counts[ev.event_type.value] += 1
        for observer in self.observers:
            observer(ev)
        self.last_event_ts = ev.timestamp if self.last_event_ts is None else max(self.last_event_ts, ev.timestamp)

        if ev.event_type is EventType.SENSOR:
            return self._emit(self._sensor_event(ev), ev)

        self.ctx.observe(ev)
        self._store(ev)
        findings = []
        for det in self.detectors:
            try:
                findings += det.process(ev, self.ctx)
            except Exception as exc:  # a detector bug must not stop monitoring
                self.stats[f"detector_error:{getattr(det, 'name', type(det).__name__)}"] += 1
                self.stats["detector_errors"] += 1
                self.last_error = repr(exc)
        alerts = self.correlator.observe_event(ev)
        if findings:
            self.stats["findings"] += len(findings)
            alerts += self.correlator.add_findings(findings)
        self._maybe_expire(ev.timestamp)
        return self._emit(alerts, ev)

    def _sensor_event(self, ev: Event) -> list[Alert]:
        status = str(ev.metadata.get("status", "")).lower()
        mapping = {"lost": SENSOR_LOST, "sensor_lost": SENSOR_LOST,
                   "recovered": SENSOR_RECOVERED, "sensor_recovered": SENSOR_RECOVERED}
        if status not in mapping:
            return []
        iface = ev.metadata.get("interface") or self.config.sensor.interface
        if self.db is not None:
            try:
                self.db.record_sensor_status(sensor=ev.sensor, interface=iface,
                                             status="ONLINE" if mapping[status] == SENSOR_RECOVERED else "LOST",
                                             backend="replay", timestamp=ev.timestamp,
                                             details={"source": "event"})
            except (sqlite3.Error, ValueError) as exc:
                self._storage_error(exc)
        return [sensor_alert(mapping[status], ev.timestamp, sensor=ev.sensor, interface=iface,
                             weight=self.config.scoring.weight("sensor_lost"))]

    def _emit(self, alerts: list[Alert], ev: Event | None) -> list[Alert]:
        for a in alerts:
            if ev is not None and not a.sensor:
                a.sensor = ev.sensor
            a.network_id = self.network_ids.get(a.network) if a.network else None
            self.stats["alerts"] += 1
            self.alerts.append(a)
            if self.sink is not None:
                self.sink(a)
        if len(self.alerts) > 10_000:
            del self.alerts[:-5_000]
        return alerts

    def emit_external(self, alert: Alert) -> None:
        """Alerts produced outside the event flow (sensor health, backend state)."""
        self._emit([alert], None)

    def _maybe_expire(self, now: float) -> None:
        # Idle state is dropped every minute of event time. Growth is bounded independently of
        # this (every per-key structure is capped when keys are added), so a capture whose
        # timestamps do not advance is safe too.
        if self._last_expire is None:
            self._last_expire = now
        elif now - self._last_expire >= 60.0:
            for det in self.detectors:
                expire = getattr(det, "expire", None)
                if expire:
                    expire(now)
            self.correlator.expire(now)
            self._last_expire = now

    # -- storage ------------------------------------------------------------------------
    def _store(self, ev: Event) -> None:
        if self.db is None:
            return
        if ev.event_type in AP_OBSERVATION_TYPES:
            self._store_ap(ev)
        elif self._event_budget.allow((ev.event_type.value, ev.bssid), ev.timestamp) and (
                self.registry.by_bssid(ev.bssid) is not None  # a flood elsewhere never costs these rows
                or self._event_total.allow(None, ev.timestamp)):
            self._events.append(ev)
        else:
            self.stats["events_not_stored"] += 1
        if ev.station and ev.bssid:
            kind = ("eapol" if ev.event_type is EventType.EAPOL else
                    "disconnect" if ev.event_type in DISCONNECT_TYPES else
                    "connect" if ev.event_type in CONNECT_TYPES else None)
            if kind:
                self._stations[(ev.station, ev.bssid, kind)] += 1
                self._station_seen[(ev.station, ev.bssid)] = ev.timestamp
        if len(self._events) >= 200 or time.monotonic() - self._last_flush > 1.0:
            self.flush()

    def _store_ap(self, ev: Event) -> None:
        key = (ev.bssid, ev.ssid or "")
        last = self._ap_written.get(key)
        sec = ev.security
        if last and ev.timestamp - last[0] < 60.0 and last[1] == sec and last[2] == ev.channel:
            return
        authorized = self.registry.is_authorized(ev.ssid, ev.bssid)
        if last is None and authorized is not True and not (
                self._unknown_ap_budget.allow(ev.ssid or "", ev.timestamp)
                and (authorized is False  # an unregistered BSSID for a protected SSID: per-SSID budget only
                     or self._unknown_ap_total.allow(None, ev.timestamp))):
            self.stats["aps_not_stored"] += 1  # beacon flood with random BSSIDs / SSIDs: keep a sample
            return
        self._ap_written[key] = (ev.timestamp, sec, ev.channel)
        self._ap_written.move_to_end(key)
        if len(self._ap_written) > MAX_AP_WRITE_KEYS:
            self._ap_written.popitem(last=False)
        net = self.registry.network_of(ev)
        try:
            self.db.upsert_ap(bssid=ev.bssid, ssid=ev.ssid,
                              network_id=self.network_ids.get(net.name) if net else None,
                              authorized=authorized, channel=ev.channel, security=sec,
                              phy=ev.metadata.get("phy"), rssi=ev.rssi, timestamp=ev.timestamp)
        except (sqlite3.Error, ValueError) as exc:
            self._storage_error(exc)

    def _storage_error(self, exc: Exception, count: int = 1) -> None:
        self.stats["storage_errors"] += count
        self.last_error = repr(exc)
        logging.getLogger("daybreak.pipeline").warning("database write failed: %s", exc)

    def flush(self) -> None:
        if self.db is None:
            return
        if self._events:
            batch, self._events = self._events, []
            try:
                self.db.insert_events(batch)
            except (sqlite3.Error, ValueError) as exc:  # dropped, counted: never retried forever
                self._storage_error(exc, len(batch))
        if self._stations:
            per_station: dict[tuple[str, str], Counter] = {}
            for (sta, bssid, kind), n in self._stations.items():
                per_station.setdefault((sta, bssid), Counter())[kind] += n
            for (sta, bssid), counts in per_station.items():
                key = (sta, bssid)
                if key in self._station_written:
                    self._station_written.move_to_end(key)
                elif not self._station_budget.allow(bssid if self.registry.by_bssid(bssid) else None,
                                                    self._station_seen[key]):
                    self.stats["stations_not_stored"] += 1  # random client MACs: keep a sample
                    continue
                else:
                    self._station_written[key] = None
                    if len(self._station_written) > MAX_STATION_WRITE_KEYS:
                        self._station_written.popitem(last=False)
                net = self.registry.by_bssid(bssid)
                try:
                    self.db.upsert_station(mac=sta, bssid=bssid,
                                           network_id=self.network_ids.get(net.name) if net else None,
                                           timestamp=self._station_seen[(sta, bssid)],
                                           eapol=counts["eapol"], disconnect=counts["disconnect"],
                                           connect=counts["connect"])
                except (sqlite3.Error, ValueError) as exc:
                    self._storage_error(exc)
            self._stations.clear()
            self._station_seen.clear()
        self._last_flush = time.monotonic()
