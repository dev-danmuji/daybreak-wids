"""Correlation: combine individual findings into explained, scored alerts.

Individual findings are reported as low-weight alerts of their own type. The
correlator groups them into *incidents* (per BSSID for disconnect/EAPOL
activity, per protected network for spoofing) and raises composite alerts
when a meaningful combination appears, e.g.::

    deauth burst + station disconnect + EAPOL activity  ->  POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT

Every alert carries the score components that produced it. Composite alerts
never claim that an attack succeeded or that a handshake was obtained.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from ..detectors.base import (
    DEAUTH_CATEGORIES, POSSIBLE_DEAUTH_ATTACK, POSSIBLE_EVIL_TWIN,
    POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT, SPOOF_CATEGORIES, DetectionContext,
)
from ..models import DISCONNECT_TYPES, Alert, Event, EventType, Finding, ScoreComponent

SUMMARIES = {
    POSSIBLE_DEAUTH_ATTACK:
        "Abnormal disconnect activity against a protected BSSID (possible deauthentication attack).",
    POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT:
        "Disconnect burst followed by re-authentication of the affected stations: consistent with an "
        "attempt to capture a WPA handshake. Whether a handshake was obtained is not determined.",
    POSSIBLE_EVIL_TWIN:
        "A BSSID that is not registered advertises a protected SSID with weaker or incompatible "
        "security (possible evil twin / rogue AP).",
}

CORE_DEAUTH = ("deauth_burst", "broadcast_deauth")
MAX_TRACKED = 1024      # stations / rogue BSSIDs remembered per incident and per BSSID
MAX_INCIDENTS = 4096
SPOOF_STRONG = {"security_downgrade", "incompatible_duplicate", "pmf_downgrade", "encryption_change"}


@dataclass
class Incident:
    key: str
    kind: str                      # "bssid" | "network"
    opened: float
    last_update: float
    network: str | None = None
    bssid: str | None = None
    ssid: str | None = None
    channel: int | None = None
    findings: dict[str, Finding] = field(default_factory=dict)       # category -> strongest
    sources: dict[str, set[str]] = field(default_factory=dict)       # category -> finding types
    disconnected: dict[str, float] = field(default_factory=dict)     # station -> first disconnect
    reauth: dict[str, float] = field(default_factory=dict)           # station -> seconds to EAPOL
    rogue_bssids: set[str] = field(default_factory=set)
    emitted: dict[str, int] = field(default_factory=dict)

    def add(self, f: Finding) -> None:
        self.last_update = max(self.last_update, f.timestamp)
        current = self.findings.get(f.category)
        keep_rogue = (self.kind == "network" and current is not None
                      and current.details.get("authorized") is False
                      and f.details.get("authorized") is not False)
        if not keep_rogue and (current is None or f.points >= current.points):
            # keep the strongest; refresh details on equal weight (e.g. escalations)
            self.findings[f.category] = f
        self.sources.setdefault(f.category, set()).add(f.finding_type)
        self.network = self.network or f.network
        self.ssid = self.ssid or f.ssid
        self.channel = f.channel or self.channel
        if self.kind == "bssid":
            for s in f.stations:
                self.note_disconnect(s, f.timestamp)
        elif f.bssid and f.details.get("authorized") is False and len(self.rogue_bssids) < MAX_TRACKED:
            self.rogue_bssids.add(f.bssid)

    def note_disconnect(self, station: str, ts: float) -> None:
        if station in self.disconnected or len(self.disconnected) < MAX_TRACKED:
            self.disconnected.setdefault(station, ts)


def _component(f: Finding, sources: set[str]) -> ScoreComponent:
    detail = f.detail
    others = sorted(s for s in sources if s != f.finding_type)
    if others:
        detail = f"{detail}; also {', '.join(others)}" if detail else f"also {', '.join(others)}"
    return ScoreComponent(f.points, f.label, detail, f.category)


class CorrelationEngine:
    def __init__(self, config: Config, ctx: DetectionContext):
        self.cfg = config.detection.correlation
        self.config = config
        self.ctx = ctx
        self.escalation = config.alerts.escalation_delta
        self.incidents: dict[str, Incident] = {}
        self.recent_disconnects: dict[str, dict[str, float]] = {}   # bssid -> station -> ts
        self.recent_reauth: dict[str, dict[str, tuple[float, float]]] = {}  # bssid -> sta -> (ts, delay)

    # -- individual findings -----------------------------------------------------------
    def finding_alert(self, f: Finding) -> Alert:
        comps = [ScoreComponent(f.points, f.label, f.detail, f.category)]
        return Alert(
            alert_type=f.finding_type, timestamp=f.timestamp, score=f.points, components=comps,
            summary=f"{f.label}: {f.detail}" if f.detail else f.label,
            network=f.network, bssid=f.bssid, ssid=f.ssid, channel=f.channel,
            details=dict(f.details), stations=tuple(sorted(f.stations)),
        )

    # -- incidents -------------------------------------------------------------------------
    def _key(self, f: Finding) -> tuple[str, str] | None:
        if f.category in SPOOF_CATEGORIES:
            scope = f.network or f.ssid
            return (f"net:{scope}", "network") if scope else None
        if f.category in DEAUTH_CATEGORIES or f.category in ("eapol_reauth_surge", "baseline_deviation"):
            return (f"bssid:{f.bssid}", "bssid") if f.bssid else None
        return None

    def _incident(self, f: Finding) -> Incident | None:
        key = self._key(f)
        if key is None:
            return None
        inc = self.incidents.get(key[0])
        if inc is not None and f.timestamp - inc.last_update > self.cfg.window:
            del self.incidents[key[0]]
            inc = None
        if inc is None:
            if key[1] == "bssid" and f.category not in DEAUTH_CATEGORIES:
                # EAPOL/baseline findings join, but do not open, disconnect incidents
                pending = self.incidents.setdefault(f"pending:{key[0]}", Incident(
                    key[0], "pending", f.timestamp, f.timestamp, bssid=f.bssid))
                pending.add(f)
                return None
            inc = Incident(key[0], key[1], f.timestamp, f.timestamp, network=f.network,
                           bssid=f.bssid if key[1] == "bssid" else None, ssid=f.ssid, channel=f.channel)
            pending = self.incidents.pop(f"pending:{key[0]}", None)
            if pending and f.timestamp - pending.last_update <= self.cfg.window:
                for cat, pf in pending.findings.items():
                    inc.findings.setdefault(cat, pf)
                    inc.sources.setdefault(cat, set()).update(pending.sources.get(cat, ()))
            if key[1] == "bssid":
                self._import_recent(inc, f.timestamp)
            self.incidents[key[0]] = inc
        return inc

    def _activity_start(self, inc: Incident) -> float:
        """Earliest time the disconnect activity behind an incident can have started."""
        return inc.opened - self.config.detection.deauth.burst_window

    def _import_recent(self, inc: Incident, now: float) -> None:
        start = self._activity_start(inc)
        for sta, ts in self.recent_disconnects.get(inc.bssid, {}).items():
            if ts >= start:
                inc.disconnected.setdefault(sta, ts)
        for sta, (ts, delay) in self.recent_reauth.get(inc.bssid, {}).items():
            if ts >= start:
                inc.reauth.setdefault(sta, delay)

    def add_findings(self, findings: list[Finding]) -> list[Alert]:
        """Add all findings produced by one event, then assess each touched incident once."""
        alerts = [self.finding_alert(f) for f in findings]
        touched: dict[str, tuple[Incident, float]] = {}
        for f in findings:
            inc = self._incident(f)
            if inc is not None:
                inc.add(f)
                prev = touched.get(inc.key)
                touched[inc.key] = (inc, max(f.timestamp, prev[1]) if prev else f.timestamp)
        for inc, ts in touched.values():
            alerts += self._assess(inc, ts)
        return alerts

    def add_finding(self, f: Finding) -> list[Alert]:
        return self.add_findings([f])

    # -- raw event sequence tracking (disconnect -> re-authentication) -------------------------
    def observe_event(self, ev: Event) -> list[Alert]:
        if not ev.bssid:
            return []
        ts = ev.timestamp
        if ev.event_type in DISCONNECT_TYPES:
            book = self.recent_disconnects.setdefault(ev.bssid, {})
            targets = [ev.station] if ev.station else (
                sorted(self.ctx.stations.associated(ev.bssid, ts)) if ev.broadcast else [])
            for sta in targets:
                book[sta] = ts
            inc = self.incidents.get(f"bssid:{ev.bssid}")
            if inc is not None:
                for sta in targets:
                    inc.note_disconnect(sta, ts)
            self._prune(ev.bssid, ts)
            return []
        # Association alone is not evidence of a handshake; EAPOL from the station is required.
        if ev.event_type is EventType.EAPOL and ev.station:
            disc = self.recent_disconnects.get(ev.bssid, {}).get(ev.station)
            if disc is not None and 0 <= ts - disc <= self.cfg.reconnect_window:
                self.recent_reauth.setdefault(ev.bssid, {}).setdefault(ev.station, (ts, ts - disc))
                inc = self.incidents.get(f"bssid:{ev.bssid}")
                if inc is not None and ev.station not in inc.reauth:
                    inc.reauth[ev.station] = round(ts - disc, 2)
                    inc.last_update = max(inc.last_update, ts)
                    return self._assess(inc, ts)
        return []

    def _prune(self, bssid: str, now: float) -> None:
        horizon = max(self.cfg.window, self.cfg.reconnect_window) * 2
        book = self.recent_disconnects.get(bssid, {})
        for sta in [s for s, t in book.items() if now - t > horizon]:
            del book[sta]
        while len(book) > MAX_TRACKED:
            del book[next(iter(book))]
        if not book:
            self.recent_disconnects.pop(bssid, None)
        reauth = self.recent_reauth.get(bssid, {})
        for sta in [s for s, (t, _) in reauth.items() if now - t > horizon]:
            del reauth[sta]
        if not reauth:
            self.recent_reauth.pop(bssid, None)

    # -- assessment ------------------------------------------------------------------------------
    def _intensity(self, inc: Incident) -> ScoreComponent | None:
        burst = inc.findings.get("deauth_burst")
        if burst is None or "frames" not in burst.details:
            return None
        thr = self.config.detection.deauth.burst_threshold
        ratio = burst.details["frames"] / max(thr, 1)
        bonus = min(10, int(5 * math.log2(ratio))) if ratio >= 2 else 0
        if bonus <= 0:
            return None
        return ScoreComponent(bonus, "burst intensity", f"{ratio:.1f}x threshold", "deauth_burst")

    def _assess(self, inc: Incident, now: float) -> list[Alert]:
        out: list[Alert] = []
        cats = inc.findings
        if inc.kind == "bssid":
            deauth = [f for c, f in cats.items() if c in DEAUTH_CATEGORIES]
            if not any(c in cats for c in CORE_DEAUTH):
                return out
            deauth.sort(key=lambda f: -f.points)
            comps = [_component(f, inc.sources.get(f.category, set())) for f in deauth]
            extra = self._intensity(inc)
            if extra:
                comps.append(extra)
            base = cats.get("baseline_deviation")
            if base is not None and base.details.get("metric") == "disconnects":
                comps.append(_component(base, set()))
            score = sum(c.points for c in comps)
            if len(deauth) >= 2 or score >= 50:
                out += self._emit(inc, POSSIBLE_DEAUTH_ATTACK, comps, now)

            eapol = cats.get("eapol_reauth_surge")
            if eapol is not None and eapol.timestamp < self._activity_start(inc):
                eapol = None  # EAPOL activity must follow the disconnects, not precede them
            if inc.disconnected and (eapol is not None or inc.reauth):
                hs = list(comps)
                if eapol is not None:
                    hs.append(_component(eapol, inc.sources.get("eapol_reauth_surge", set())))
                if inc.reauth:
                    delays = sorted(inc.reauth.values())
                    hs.append(ScoreComponent(
                        self.ctx.weight("reconnect_after_disconnect"),
                        "disconnected stations re-authenticated",
                        f"{len(inc.reauth)} station(s), EAPOL {delays[0]:.1f}s after disconnect",
                        "reconnect_after_disconnect"))
                if base is not None and base.details.get("metric") == "eapol":
                    hs.append(_component(base, set()))
                out += self._emit(inc, POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT, hs, now)
        elif inc.kind == "network":
            spoof = {c: f for c, f in cats.items() if c in SPOOF_CATEGORIES}
            unknown = "unknown_bssid" in spoof
            conflict = any(f.details.get("bssid_conflict") for f in spoof.values())
            # weaker/incompatible security must come from a BSSID that is not registered
            rogue_strong = [c for c in SPOOF_STRONG if c in spoof and spoof[c].details.get("authorized") is False]
            if (unknown and rogue_strong) or conflict:
                ordered = sorted(spoof.values(), key=lambda f: -f.points)
                comps = [_component(f, inc.sources.get(f.category, set())) for f in ordered]
                deauth_live = [i for i in self.incidents.values()
                               if i.kind == "bssid" and i.network == inc.network
                               and now - i.last_update <= self.cfg.window
                               and any(c in i.findings for c in CORE_DEAUTH)]
                if deauth_live:
                    comps.append(ScoreComponent(
                        self.ctx.weight("concurrent_deauth"), "concurrent disconnect activity",
                        f"on {', '.join(sorted({i.bssid for i in deauth_live if i.bssid}))}",
                        "concurrent_deauth"))
                out += self._emit(inc, POSSIBLE_EVIL_TWIN, comps, now)
        return out

    def _emit(self, inc: Incident, alert_type: str, comps: list[ScoreComponent], now: float) -> list[Alert]:
        score = min(100, sum(c.points for c in comps))
        last = inc.emitted.get(alert_type)
        if last is not None and score < last + self.escalation:
            return []
        inc.emitted[alert_type] = score
        details: dict[str, Any] = {"incident_opened": inc.opened, "correlation_window": self.cfg.window}
        burst = inc.findings.get("deauth_burst")
        if burst is not None:
            for key in ("frames", "window", "reason_codes", "top_reason"):
                if key in burst.details:
                    details[key] = burst.details[key]
        if inc.kind == "bssid":
            details["affected_stations"] = len(inc.disconnected)
            if inc.reauth:
                details["reauthenticated_stations"] = len(inc.reauth)
            stations = tuple(sorted(inc.disconnected))
        else:
            details["rogue_bssids"] = sorted(inc.rogue_bssids)
            stations = ()
        details["evidence"] = sorted(t for s in inc.sources.values() for t in s)
        return [Alert(
            alert_type=alert_type, timestamp=now, score=score, components=list(comps),
            summary=SUMMARIES[alert_type], network=inc.network,
            bssid=inc.bssid or (sorted(inc.rogue_bssids)[0] if inc.rogue_bssids else None),
            ssid=inc.ssid, channel=inc.channel, details=details, stations=stations,
        )]

    def expire(self, now: float) -> None:
        for key in [k for k, i in self.incidents.items() if now - i.last_update > self.cfg.window * 2]:
            del self.incidents[key]
        if len(self.incidents) > MAX_INCIDENTS:  # a flood of random BSSIDs: keep the most active
            keep = sorted(self.incidents.items(), key=lambda kv: kv[1].last_update)[-MAX_INCIDENTS:]
            self.incidents = dict(keep)
        for bssid in set(self.recent_disconnects) | set(self.recent_reauth):
            self._prune(bssid, now)
