"""Baselines: what "normal" looks like for each protected network.

A baseline is learned from a period of observation (live, a replayed
recording, or events already stored in SQLite) and stored in the
``baselines`` table. It contains per-minute activity rates, the BSSIDs,
channels and security capabilities seen, per-BSSID RSSI statistics and the
client count range.

Deviation scoring uses robust statistics (median and MAD) so that a few
unusual minutes during learning do not inflate "normal", and additionally
requires the current rate to exceed the highest rate seen while learning.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from ..config import BaselineConfig, Config
from ..detectors.base import BASELINE_DEVIATION, DetectionContext, RunningStats, finding
from ..detectors.window import KeyedState, SlidingWindow, Trigger
from ..models import (
    AP_OBSERVATION_TYPES, CONNECT_TYPES, DISCONNECT_TYPES, Event, EventType, Finding, SecurityProfile,
)
from ..registry import NetworkRegistry

METRICS = ("disconnects", "eapol", "connects")
METRIC_LABEL = {"disconnects": "disconnect frames", "eapol": "EAPOL frames", "connects": "(re)connections"}


def metric_of(ev: Event) -> str | None:
    if ev.event_type in DISCONNECT_TYPES:
        return "disconnects"
    if ev.event_type is EventType.EAPOL:
        return "eapol"
    if ev.event_type in CONNECT_TYPES:
        return "connects"
    return None


def describe_rates(values: list[float]) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "std": 0.0, "median": 0.0, "mad": 0.0, "p95": 0.0, "max": 0.0}
    ordered = sorted(values)
    median = statistics.median(ordered)
    mad = statistics.median([abs(v - median) for v in ordered])
    p95 = ordered[min(len(ordered) - 1, math.ceil(0.95 * len(ordered)) - 1)]
    return {
        "mean": round(statistics.fmean(ordered), 3),
        "std": round(statistics.pstdev(ordered), 3) if len(ordered) > 1 else 0.0,
        "median": float(median), "mad": float(mad), "p95": float(p95), "max": float(ordered[-1]),
    }


# ---------------------------------------------------------------------------
# Learning
# ---------------------------------------------------------------------------


@dataclass
class _NetAccumulator:
    buckets: dict[int, Counter] = field(default_factory=dict)
    clients: dict[int, set] = field(default_factory=dict)
    bssid_rssi: dict[str, RunningStats] = field(default_factory=dict)
    bssid_channels: dict[str, Counter] = field(default_factory=dict)
    bssid_security: dict[str, Counter] = field(default_factory=dict)
    profiles: dict[tuple, SecurityProfile] = field(default_factory=dict)
    bssid_obs: Counter = field(default_factory=Counter)
    candidates: set = field(default_factory=set)
    events: int = 0


class BaselineBuilder:
    def __init__(self, config: Config, registry: NetworkRegistry | None = None):
        self.cfg: BaselineConfig = config.detection.baseline
        self.registry = registry or NetworkRegistry(config.protected_networks)
        self.nets: dict[str, _NetAccumulator] = {n.name: _NetAccumulator() for n in self.registry.networks}
        self.start: float | None = None
        self.end: float | None = None
        self.events = 0

    def add(self, ev: Event) -> None:
        net = self.registry.network_of(ev)
        if net is None:
            return
        self.events += 1
        self.start = ev.timestamp if self.start is None else min(self.start, ev.timestamp)
        self.end = ev.timestamp if self.end is None else max(self.end, ev.timestamp)
        acc = self.nets[net.name]
        acc.events += 1
        if ev.event_type in AP_OBSERVATION_TYPES:
            if ev.bssid not in net.bssids:
                acc.candidates.add(ev.bssid)
                return
            acc.bssid_obs[ev.bssid] += 1
            if ev.channel:
                acc.bssid_channels.setdefault(ev.bssid, Counter())[ev.channel] += 1
            if ev.rssi is not None and ev.metadata.get("source_backend") != "kismet":
                acc.bssid_rssi.setdefault(ev.bssid, RunningStats()).add(ev.rssi)
            if ev.security is not None:
                sig = ev.security.signature()
                acc.profiles.setdefault(sig, ev.security)
                acc.bssid_security.setdefault(ev.bssid, Counter())[sig] += 1
            return
        metric = metric_of(ev)
        if metric is None:
            return
        idx = int(ev.timestamp // self.cfg.bucket)
        acc.buckets.setdefault(idx, Counter())[metric] += 1
        if ev.station:
            acc.clients.setdefault(idx, set()).add(ev.station)

    def add_ap_row(self, row: Mapping[str, Any]) -> None:
        """Seed AP knowledge from an ``aps`` table row (beacons are not stored as events)."""
        sec = row.get("security")
        try:
            profile = SecurityProfile.from_dict(sec) if isinstance(sec, Mapping) else None
        except ValueError:
            profile = None
        ev = Event(timestamp=float(row["last_seen"]), event_type=EventType.BEACON, bssid=row["bssid"],
                   source=row["bssid"], ssid=row.get("ssid") or None, channel=row.get("channel"),
                   security=profile, metadata={"source_backend": "kismet"})  # no RSSI statistics from rows
        net = self.registry.network_of(ev)
        if net is None:
            return
        acc = self.nets[net.name]
        if ev.bssid not in net.bssids:
            acc.candidates.add(ev.bssid)
            return
        acc.bssid_obs[ev.bssid] += int(row.get("observations") or 1)
        if ev.channel:
            acc.bssid_channels.setdefault(ev.bssid, Counter())[ev.channel] += 1
        if profile is not None:
            sig = profile.signature()
            acc.profiles.setdefault(sig, profile)
            acc.bssid_security.setdefault(ev.bssid, Counter())[sig] += 1

    def metrics(self) -> dict[str, dict[str, Any]]:
        """Per-network baseline documents (JSON-serialisable)."""
        out: dict[str, dict[str, Any]] = {}
        if self.start is None or self.end is None:
            return out
        first, last = int(self.start // self.cfg.bucket), int(self.end // self.cfg.bucket)
        indices = range(first, last + 1)
        for net in self.registry.networks:
            acc = self.nets[net.name]
            rates = {m: describe_rates([float(acc.buckets.get(i, Counter())[m]) for i in indices])
                     for m in METRICS}
            client_counts = [len(acc.clients.get(i, ())) for i in indices]
            active = [c for c in client_counts if c]
            bssids = {}
            for b in sorted(acc.bssid_obs):
                st = acc.bssid_rssi.get(b)
                sec_counter = acc.bssid_security.get(b)
                sec = acc.profiles[sec_counter.most_common(1)[0][0]].to_dict() if sec_counter else None
                bssids[b] = {
                    "observations": acc.bssid_obs[b],
                    "channels": sorted(acc.bssid_channels.get(b, Counter())),
                    "rssi": {"mean": round(st.mean, 1), "std": round(st.std, 2), "n": st.n} if st else None,
                    "security": sec,
                    "profiles_seen": len(sec_counter) if sec_counter else 0,
                }
            strongest = None
            for b, info in bssids.items():
                if info["security"]:
                    prof = SecurityProfile.from_dict(info["security"])
                    if strongest is None or prof.rank > strongest.rank:
                        strongest = prof
            out[net.name] = {
                "version": 1,
                "network": net.name,
                "ssid": net.ssid,
                "window": [self.start, self.end],
                "duration": round(self.end - self.start, 1),
                "bucket": self.cfg.bucket,
                "buckets": len(indices),
                "events": acc.events,
                "rates": rates,
                "clients": {"min": min(active) if active else 0, "max": max(client_counts) if client_counts else 0,
                            "mean": round(statistics.fmean(client_counts), 2) if client_counts else 0.0},
                "bssids": bssids,
                "known_bssids": sorted(bssids),
                "known_channels": sorted({c for info in bssids.values() for c in info["channels"]}),
                "security": strongest.to_dict() if strongest else None,
                "candidate_bssids": sorted(acc.candidates),
            }
        return out


def save_baselines(db: Any, metrics: Mapping[str, Mapping[str, Any]], network_ids: Mapping[str, int]) -> dict[str, int]:
    saved = {}
    for name, doc in metrics.items():
        start, end = doc["window"]
        saved[name] = db.save_baseline(network_id=network_ids.get(name), window_start=start,
                                       window_end=end, metrics=doc)
    return saved


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


class BaselineStore:
    def __init__(self, docs: Mapping[str, Mapping[str, Any]]):
        self.docs = dict(docs)
        self._rssi: dict[str, tuple[float, float, int]] = {}
        self._bssid_sec: dict[str, SecurityProfile] = {}
        self._bssid_channels: dict[str, set[int]] = {}
        for doc in self.docs.values():
            for b, info in (doc.get("bssids") or {}).items():
                r = info.get("rssi")
                if r and r.get("n", 0) >= 10:
                    self._rssi[b] = (float(r["mean"]), float(r["std"]), int(r["n"]))
                if info.get("security"):
                    try:
                        self._bssid_sec[b] = SecurityProfile.from_dict(info["security"])
                    except ValueError:
                        pass
                self._bssid_channels[b] = set(info.get("channels") or [])

    @classmethod
    def from_db(cls, db: Any) -> "BaselineStore":
        return cls({row["network"]: row["metrics"] for row in db.active_baselines() if row.get("network")})

    def __bool__(self) -> bool:
        return bool(self.docs)

    def security_for(self, network: str | None, bssid: str | None) -> SecurityProfile | None:
        if bssid and bssid in self._bssid_sec:
            return self._bssid_sec[bssid]
        doc = self.docs.get(network or "")
        if bssid is None and doc and doc.get("security"):
            return SecurityProfile.from_dict(doc["security"])
        return None

    def rssi_for(self, bssid: str) -> tuple[float, float, int] | None:
        return self._rssi.get(bssid)

    def channels_for(self, bssid: str) -> set[int]:
        return self._bssid_channels.get(bssid, set())

    def rate(self, network: str, metric: str) -> dict[str, float] | None:
        doc = self.docs.get(network)
        if not doc:
            return None
        return (doc.get("rates") or {}).get(metric)

    def bucket(self, network: str) -> float | None:
        doc = self.docs.get(network)
        return float(doc["bucket"]) if doc and doc.get("bucket") else None


# ---------------------------------------------------------------------------
# Deviation detector
# ---------------------------------------------------------------------------


def deviation(value: float, rate: Mapping[str, float], cfg: BaselineConfig) -> tuple[float, float]:
    """Return (robust z-score, sigma used)."""
    sigma = max(1.4826 * float(rate.get("mad", 0.0)), cfg.min_sigma)
    return (value - float(rate.get("median", rate.get("mean", 0.0)))) / sigma, sigma


class BaselineDetector:
    name = "baseline"

    def __init__(self, cfg: BaselineConfig):
        self.cfg = cfg
        self.windows: KeyedState[tuple[str, str], tuple[SlidingWindow, Trigger]] = KeyedState(
            lambda: (SlidingWindow(cfg.bucket), Trigger(1, rearm_after=cfg.bucket * 5)))

    def process(self, ev: Event, ctx: DetectionContext) -> list[Finding]:
        store = ctx.baseline
        if not store:
            return []
        metric = metric_of(ev)
        if metric is None:
            return []
        net = ctx.registry.network_of(ev)
        if net is None:
            return []
        rate = store.rate(net.name, metric)
        if rate is None:
            return []
        window, trigger = self.windows.get((net.name, metric), ev.timestamp)
        window.add(ev.timestamp)
        value = window.count(ev.timestamp)
        z, _sigma = deviation(value, rate, self.cfg)
        peak = float(rate.get("max", 0.0))
        anomalous = value >= self.cfg.min_count and z >= self.cfg.z_threshold and value > peak
        if not trigger.update(1 if anomalous else 0, ev.timestamp):
            return []
        weight = ctx.weight("baseline_deviation")
        points = weight if value > 2 * max(peak, self.cfg.min_count) else round(weight * 0.6)
        per = f"{self.cfg.bucket:g}s"
        return [finding(
            BASELINE_DEVIATION, ev, ctx, category="baseline_deviation", label="baseline deviation",
            detail=(f"{int(value)} {METRIC_LABEL[metric]}/{per} vs normal median {rate.get('median', 0):g} "
                    f"(max {peak:g}), z={z:.1f}"),
            network=net, points=points,
            details={"metric": metric, "value": value, "median": rate.get("median"), "mean": rate.get("mean"),
                     "max": peak, "z": round(z, 2), "bucket": self.cfg.bucket},
        )]

    def expire(self, now: float) -> None:
        self.windows.evict_idle(now)


def build_from_events(config: Config, events: Iterable[Event]) -> dict[str, dict[str, Any]]:
    builder = BaselineBuilder(config)
    for ev in events:
        builder.add(ev)
    return builder.metrics()
