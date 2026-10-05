"""Passive deauthentication / disassociation analysis (metadata only).

A single deauth/disassoc is normal (roaming, AP restarts, idle timeouts), so
nothing here alerts on one frame. Detection is window/threshold based and the
resulting findings are weighted and correlated before an alert is raised.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from ..config import DeauthConfig
from ..dot11.ieee80211 import is_valid_reason, reason_text
from ..models import Event, Finding
from .base import (
    BROADCAST_DEAUTH, DEAUTH_BURST, INVALID_REASON_CODE, MULTI_CLIENT_DEAUTH, SUSPICIOUS_SOURCE,
    DetectionContext, finding,
)
from .window import KeyedState, SlidingWindow, Trigger


@dataclass
class _BssidState:
    frames: SlidingWindow
    bcast: SlidingWindow
    targets: SlidingWindow
    suspicious: SlidingWindow
    invalid: SlidingWindow
    burst: Trigger
    bcast_t: Trigger
    multi_t: Trigger
    susp_t: Trigger
    invalid_t: Trigger
    totals: Counter = field(default_factory=Counter)


class DeauthDetector:
    name = "deauth"

    def __init__(self, cfg: DeauthConfig):
        self.cfg = cfg
        c = cfg
        self.state: KeyedState[str, _BssidState] = KeyedState(lambda: _BssidState(
            frames=SlidingWindow(c.burst_window),
            bcast=SlidingWindow(c.broadcast_window),
            targets=SlidingWindow(c.multi_client_window),
            suspicious=SlidingWindow(c.suspicious_window),
            invalid=SlidingWindow(60.0),
            burst=Trigger(c.burst_threshold, strict=True, rearm_after=c.burst_window * 6),
            bcast_t=Trigger(c.broadcast_threshold, rearm_after=c.broadcast_window),
            multi_t=Trigger(c.multi_client_threshold, rearm_after=c.multi_client_window),
            susp_t=Trigger(c.suspicious_min_frames, rearm_after=c.suspicious_window, escalate_factor=0),
            invalid_t=Trigger(1, rearm_after=60.0, escalate_factor=4.0),
        ))

    # -- helpers -----------------------------------------------------------------
    def _suspicious_traits(self, ev: Event, ctx: DetectionContext) -> list[str]:
        """Characteristics that differ from the genuine AP (only for frames claiming to be the AP)."""
        net = ctx.registry.by_bssid(ev.bssid)
        if net is None or ev.source != ev.bssid:
            return []
        traits = []
        profile = ctx.rssi_profile(ev.bssid)
        if profile and ev.rssi is not None:
            mean, std, _n = profile
            limit = max(self.cfg.rssi_deviation_db, 4 * std)
            if abs(ev.rssi - mean) > limit:
                traits.append(f"RSSI {ev.rssi} dBm vs AP {mean:.0f}±{std:.0f} dBm")
        if ev.protected is False and ctx.pmf_required(net, ev.bssid):
            traits.append("unprotected frame although the network requires PMF")
        if ev.channel and net.channels and ev.channel not in net.channels:
            near_24 = ev.channel <= 14 and any(c <= 14 and abs(c - ev.channel) <= 4 for c in net.channels)
            if not near_24:
                traits.append(f"seen on channel {ev.channel}, AP uses {','.join(map(str, net.channels))}")
        if ev.reason_code is not None and not is_valid_reason(ev.reason_code):
            traits.append(f"invalid reason code {ev.reason_code}")
        return traits

    # -- main ----------------------------------------------------------------------
    def process(self, ev: Event, ctx: DetectionContext) -> list[Finding]:
        if not ev.is_disconnect or not ev.bssid:
            return []
        ts = ev.timestamp
        st = self.state.get(ev.bssid, ts)
        st.totals[ev.event_type.value] += 1
        out: list[Finding] = []
        target = ev.station or ev.destination

        # 1) burst: more than N disconnect frames within the window
        st.frames.add(ts, (ev.event_type, target, ev.reason_code, ev.broadcast))
        n = st.frames.count(ts)
        action = st.burst.update(n, ts)
        if action:
            items = st.frames.values(ts)
            kinds = Counter(k.value for k, *_ in items)
            reasons = Counter(r for _, _, r, _ in items if r is not None)
            stations = {t for _, t, _, b in items if t and not b}
            out.append(finding(
                DEAUTH_BURST, ev, ctx, category="deauth_burst", label="deauth burst",
                detail=f"{n} frames/{self.cfg.burst_window:g}s, threshold >{self.cfg.burst_threshold}",
                stations=stations,
                details={"frames": n, "window": self.cfg.burst_window, "deauth": kinds.get("deauth", 0),
                         "disassoc": kinds.get("disassoc", 0),
                         "broadcast": sum(1 for *_, b in items if b),
                         "reason_codes": {str(k): v for k, v in reasons.most_common(5)},
                         "top_reason": reason_text(reasons.most_common(1)[0][0]) if reasons else None,
                         "escalation": action == "escalate"},
            ))

        # 2) repeated broadcast/multicast disconnects from one BSSID
        if ev.broadcast:
            st.bcast.add(ts, ev.event_type.value)
            nb = st.bcast.count(ts)
            if st.bcast_t.update(nb, ts):
                assoc = ctx.stations.associated(ev.bssid, ts)
                out.append(finding(
                    BROADCAST_DEAUTH, ev, ctx, category="broadcast_deauth", label="broadcast disconnect",
                    detail=f"{nb} broadcast/multicast frames in {self.cfg.broadcast_window:g}s",
                    stations=assoc,
                    details={"frames": nb, "window": self.cfg.broadcast_window,
                             "associated_stations": len(assoc), "protected": bool(ev.protected)},
                ))

        # 3) many distinct stations targeted
        if ev.station:
            st.targets.add(ts, ev.station)
            targets = st.targets.distinct(ts)
            if st.multi_t.update(len(targets), ts):
                out.append(finding(
                    MULTI_CLIENT_DEAUTH, ev, ctx, category="multi_client_deauth",
                    label="multiple stations affected",
                    detail=f"{len(targets)} stations in {self.cfg.multi_client_window:g}s",
                    stations=targets,
                    details={"stations": len(targets), "window": self.cfg.multi_client_window},
                ))

        # 4) frames claiming the protected AP but not looking like it
        traits = self._suspicious_traits(ev, ctx)
        if traits:
            st.suspicious.add(ts, tuple(traits))
            ns = st.suspicious.count(ts)
            if st.susp_t.update(ns, ts):
                seen = Counter(t.split(" vs ")[0] if t.startswith("RSSI") else t
                               for group in st.suspicious.values(ts) for t in group)
                out.append(finding(
                    SUSPICIOUS_SOURCE, ev, ctx, category="suspicious_source", label="suspicious source",
                    detail=f"{ns} frames claiming {ev.bssid}: {traits[0]}",
                    stations={target} if target and not ev.broadcast else set(),
                    details={"frames": ns, "traits": dict(seen.most_common(6))},
                ))

        # 5) reserved / invalid reason codes
        if ev.reason_code is not None and not is_valid_reason(ev.reason_code):
            st.invalid.add(ts, ev.reason_code)
            ni = st.invalid.count(ts)
            if st.invalid_t.update(ni, ts):
                out.append(finding(
                    INVALID_REASON_CODE, ev, ctx, category="invalid_reason_code",
                    label="invalid reason code",
                    detail=f"reason {ev.reason_code} ({ni} in 60s)",
                    details={"reason_code": ev.reason_code, "frames": ni},
                ))
        return out

    def expire(self, now: float) -> None:
        self.state.evict_idle(now)

    def totals(self, bssid: str) -> dict[str, int]:
        st = self.state.peek(bssid)
        return dict(st.totals) if st else {}
