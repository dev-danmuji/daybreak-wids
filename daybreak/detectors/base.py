"""Detector interface, shared detection context and finding/alert type names."""

from __future__ import annotations

import math
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from ..config import Config, ProtectedNetwork
from ..models import (
    AP_OBSERVATION_TYPES, CONNECT_TYPES, Event, EventType, Finding, SecurityProfile, is_group_address,
)
from ..registry import NetworkRegistry

# -- finding types (individual detector observations) --------------------------------------
DEAUTH_BURST = "DEAUTH_BURST"
BROADCAST_DEAUTH = "BROADCAST_DEAUTH"
MULTI_CLIENT_DEAUTH = "MULTI_CLIENT_DEAUTH"
SUSPICIOUS_SOURCE = "SUSPICIOUS_SOURCE"
INVALID_REASON_CODE = "INVALID_REASON_CODE"
EAPOL_REAUTH_SURGE = "EAPOL_REAUTH_SURGE"
UNKNOWN_BSSID = "UNKNOWN_BSSID_FOR_PROTECTED_SSID"
SECURITY_DOWNGRADE = "SECURITY_DOWNGRADE"
ENCRYPTION_CHANGE = "ENCRYPTION_CHANGE"
PMF_DOWNGRADE = "PMF_DOWNGRADE"
CHANNEL_ANOMALY = "CHANNEL_ANOMALY"
INCOMPATIBLE_DUPLICATE_SSID = "INCOMPATIBLE_DUPLICATE_SSID"
BASELINE_DEVIATION = "BASELINE_DEVIATION"

# -- correlated alert types ------------------------------------------------------------------
POSSIBLE_DEAUTH_ATTACK = "POSSIBLE_DEAUTH_ATTACK"
POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT = "POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT"
POSSIBLE_EVIL_TWIN = "POSSIBLE_EVIL_TWIN"
SENSOR_LOST = "SENSOR_LOST"
SENSOR_RECOVERED = "SENSOR_RECOVERED"

DEAUTH_CATEGORIES = frozenset({"deauth_burst", "broadcast_deauth", "multi_client_deauth",
                               "suspicious_source", "invalid_reason_code"})
EAPOL_CATEGORIES = frozenset({"eapol_reauth_surge"})
SPOOF_CATEGORIES = frozenset({"unknown_bssid", "security_downgrade", "encryption_change",
                              "pmf_downgrade", "channel_anomaly", "incompatible_duplicate"})


class Detector(Protocol):
    name: str

    def process(self, event: Event, ctx: "DetectionContext") -> list[Finding]:
        ...


# ---------------------------------------------------------------------------
# Shared state: what the sensor has learned about APs and stations
# ---------------------------------------------------------------------------


@dataclass
class RunningStats:
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def add(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)

    @property
    def std(self) -> float:
        return math.sqrt(self.m2 / (self.n - 1)) if self.n > 1 else 0.0


@dataclass
class APState:
    bssid: str
    ssid: str | None
    first_seen: float
    last_seen: float
    channel: int | None = None
    channels: set[int] = field(default_factory=set)
    security: SecurityProfile | None = None
    history: deque = field(default_factory=lambda: deque(maxlen=16))  # (ts, SecurityProfile)
    rssi: RunningStats = field(default_factory=RunningStats)
    phy: dict[str, Any] = field(default_factory=dict)
    observations: int = 0


class APTracker:
    """Per-BSSID view built from beacons / probe responses / Kismet AP records.

    Bounded: beyond ``max_aps`` the least recently seen BSSID that is not registered
    (``keep``) is forgotten, so a flood of random BSSIDs cannot grow memory without limit.
    """

    def __init__(self, max_aps: int = 4096, keep: Callable[[str], bool] | None = None):
        self.aps: OrderedDict[str, APState] = OrderedDict()
        self.max_aps = max_aps
        self.keep = keep or (lambda bssid: False)
        self.evicted = 0

    def _evict(self) -> None:
        victim = next((b for b in self.aps if not self.keep(b)), None)
        if victim is not None:
            del self.aps[victim]
            self.evicted += 1

    def observe(self, ev: Event) -> tuple[APState, APState | None]:
        """Record an AP observation. Returns (current state, snapshot before the update)."""
        st = self.aps.get(ev.bssid)
        prev = None
        if st is None:
            st = self.aps[ev.bssid] = APState(ev.bssid, ev.ssid, ev.timestamp, ev.timestamp)
            if len(self.aps) > self.max_aps:
                self._evict()
        else:
            self.aps.move_to_end(ev.bssid)
            prev = APState(st.bssid, st.ssid, st.first_seen, st.last_seen, st.channel, set(st.channels),
                           st.security, deque(st.history, maxlen=16), st.rssi, dict(st.phy), st.observations)
        st.last_seen = max(st.last_seen, ev.timestamp)
        st.observations += 1
        if ev.ssid:
            st.ssid = ev.ssid
        if ev.channel:
            st.channel = ev.channel
            st.channels.add(ev.channel)
        if ev.security is not None:
            if not ev.security.same_capabilities(st.security):
                st.history.append((ev.timestamp, ev.security))
            st.security = ev.security
        if ev.rssi is not None and ev.metadata.get("source_backend") != "kismet":
            st.rssi.add(ev.rssi)
        if isinstance(ev.metadata.get("phy"), dict):
            st.phy = dict(ev.metadata["phy"])
        return st, prev

    def get(self, bssid: str | None) -> APState | None:
        return self.aps.get(bssid) if bssid else None


class StationTracker:
    """Which stations were recently seen talking to which BSSID (bounded per BSSID and overall)."""

    MAX_PER_BSSID = 1024
    MAX_BSSIDS = 4096

    def __init__(self, ttl: float = 900.0):
        self.ttl = ttl
        # LRU order on both levels: eviction is O(1) even while a flood keeps adding entries
        self.seen: OrderedDict[str, OrderedDict[str, float]] = OrderedDict()

    def observe(self, ev: Event) -> None:
        if not ev.bssid or not ev.station or is_group_address(ev.station):
            return
        if ev.event_type in CONNECT_TYPES or ev.event_type is EventType.EAPOL:
            stations = self.seen.get(ev.bssid)
            if stations is None:
                stations = self.seen[ev.bssid] = OrderedDict()
                if len(self.seen) > self.MAX_BSSIDS:
                    self.seen.popitem(last=False)
            else:
                self.seen.move_to_end(ev.bssid)
            stations[ev.station] = ev.timestamp
            stations.move_to_end(ev.station)
            if len(stations) > self.MAX_PER_BSSID:
                stations.popitem(last=False)

    def associated(self, bssid: str, now: float) -> set[str]:
        stations = self.seen.get(bssid, {})
        stale = [s for s, t in stations.items() if now - t > self.ttl]
        for s in stale:
            del stations[s]
        return set(stations)


class DetectionContext:
    def __init__(self, config: Config, registry: NetworkRegistry, *, baseline: Any = None):
        self.config = config
        self.registry = registry
        self.aps = APTracker(keep=lambda bssid: registry.by_bssid(bssid) is not None)
        self.stations = StationTracker()
        self.baseline = baseline  # daybreak.baseline.engine.BaselineStore or None
        self.last_ap_update: tuple[APState, APState | None] | None = None

    def weight(self, name: str) -> int:
        return self.config.scoring.weight(name)

    def observe(self, ev: Event) -> tuple[APState, APState | None] | None:
        """Update shared trackers; returns (and remembers) the AP update for AP observations."""
        self.stations.observe(ev)
        self.last_ap_update = None
        if ev.event_type in AP_OBSERVATION_TYPES and ev.bssid:
            self.last_ap_update = self.aps.observe(ev)
        return self.last_ap_update

    def network_for(self, ev: Event) -> ProtectedNetwork | None:
        return self.registry.network_of(ev)

    def pmf_required(self, network: ProtectedNetwork | None, bssid: str | None) -> bool:
        if network is not None and network.security.pmf == "required":
            return True
        ap = self.aps.get(bssid)
        if ap and ap.security is not None and ap.security.mfp_required:
            return True
        if self.baseline is not None and network is not None:
            prof = self.baseline.security_for(network.name, bssid)
            if prof is not None and prof.mfp_required:
                return True
        return False

    def rssi_profile(self, bssid: str | None) -> tuple[float, float, int] | None:
        ap = self.aps.get(bssid)
        if ap and ap.rssi.n >= 10:
            return ap.rssi.mean, ap.rssi.std, ap.rssi.n
        if self.baseline is not None and bssid:
            return self.baseline.rssi_for(bssid)
        return None


def finding(ftype: str, ev: Event, ctx: DetectionContext, *, category: str, label: str,
            detail: str = "", stations: set[str] | frozenset[str] = frozenset(),
            details: dict[str, Any] | None = None, points: int | None = None,
            network: ProtectedNetwork | None = None, bssid: str | None = None,
            ssid: str | None = None) -> Finding:
    net = network or ctx.network_for(ev)
    return Finding(
        finding_type=ftype,
        timestamp=ev.timestamp,
        category=category,
        points=ctx.weight(category) if points is None else points,
        label=label,
        detail=detail,
        bssid=bssid or ev.bssid,
        network=net.name if net else None,
        ssid=ssid or ev.ssid or (net.ssid if net else None),
        channel=ev.channel,
        stations=frozenset(stations),
        details=dict(details or {}),
        source="kismet" if ev.event_type is EventType.KISMET_ALERT else "daybreak",
    )
