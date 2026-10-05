"""AP spoof / evil twin / security downgrade detection for protected SSIDs.

The reference for "what the protected network should look like" is, in order:
the registry expectations (``security.expected`` / ``security.pmf``), the
learned baseline, and the capabilities observed from registered BSSIDs. A new
BSSID for a protected SSID is reported as ``UNKNOWN_BSSID_FOR_PROTECTED_SSID``
and is *not* by itself treated as an attack.

Each category is reported at most once per (BSSID, advertised profile) per
hour, with all reasons for it combined into one finding.
"""

from __future__ import annotations

from ..config import ProtectedNetwork, SpoofConfig
from ..models import AP_OBSERVATION_TYPES, PMF_LEVELS, Event, Finding, SecurityProfile
from .base import (
    CHANNEL_ANOMALY, ENCRYPTION_CHANGE, INCOMPATIBLE_DUPLICATE_SSID, PMF_DOWNGRADE, SECURITY_DOWNGRADE,
    UNKNOWN_BSSID, DetectionContext, finding,
)

REPORT_INTERVAL = 3600.0
FLAP_WINDOW = 120.0
FLAP_CHANGES = 3

_EXPECTED_RANK = {
    frozenset({"OPEN"}): 0, frozenset({"WEP"}): 1, frozenset({"WPA"}): 2, frozenset({"OWE"}): 2,
    frozenset({"WPA", "WPA2"}): 2, frozenset({"WPA2"}): 3, frozenset({"WPA2", "WPA3"}): 4,
    frozenset({"WPA3"}): 5,
}

_CATEGORY = {
    "security_downgrade": (SECURITY_DOWNGRADE, "security downgrade"),
    "pmf_downgrade": (PMF_DOWNGRADE, "PMF capability missing"),
    "encryption_change": (ENCRYPTION_CHANGE, "encryption capability change"),
    "incompatible_duplicate": (INCOMPATIBLE_DUPLICATE_SSID, "duplicate SSID with incompatible security"),
    "channel_anomaly": (CHANNEL_ANOMALY, "channel anomaly"),
}


def expected_rank(expected: list[str]) -> int | None:
    if not expected:
        return None
    key = frozenset(expected)
    if key in _EXPECTED_RANK:
        return _EXPECTED_RANK[key]
    return min(_EXPECTED_RANK.get(frozenset({e}), 3) for e in expected)


def describe(sec: SecurityProfile | None) -> str:
    return "unknown" if sec is None else f"{sec.mode}, PMF {sec.pmf}"


def _downgraded(sec: SecurityProfile, ref: SecurityProfile) -> bool:
    return sec.rank < ref.rank or ("WPA3" in ref.protocols and "WPA3" not in sec.protocols)


def _similar(bssid: str, authorized: list[str]) -> str | None:
    """A registered BSSID differing only in the last octet (another radio of the same AP?)."""
    return next((b for b in authorized if b[:14] == bssid[:14] and b != bssid), None)


class SpoofDetector:
    name = "spoof"

    def __init__(self, cfg: SpoofConfig):
        self.cfg = cfg
        self._reported: dict[tuple, float] = {}

    def _once(self, key: tuple, ts: float) -> bool:
        last = self._reported.get(key)
        if last is not None and ts - last < REPORT_INTERVAL:
            return False
        self._reported[key] = ts
        return True

    def _reference(self, net: ProtectedNetwork, ctx: DetectionContext) -> SecurityProfile | None:
        """Strongest profile seen from a registered BSSID (live, else baseline)."""
        best = None
        for b in net.bssids:
            ap = ctx.aps.get(b)
            if ap and ap.security is not None and (best is None or ap.security.rank > best.rank):
                best = ap.security
        if best is None and ctx.baseline is not None:
            best = ctx.baseline.security_for(net.name, None)
        return best

    @staticmethod
    def _register_hint(net: ProtectedNetwork, bssid: str, ctx: DetectionContext) -> str:
        if net.origin == "registry":
            existing = " ".join(f"--bssid {b}" for b in net.bssids)
            return (f"if {bssid} is your own AP/extender, register it: daybreak-wids network add "
                    f"--name {net.name} --ssid '{net.ssid}' {existing} --bssid {bssid} --replace")
        where = ctx.config.path or "config.yaml"
        return f"if {bssid} is your own AP/extender, add it to the bssids of '{net.name}' in {where}"

    @staticmethod
    def _network(ev: Event, ctx: DetectionContext) -> ProtectedNetwork | None:
        nets = ctx.registry.by_ssid(ev.ssid)
        for n in nets:
            if ev.bssid in n.bssids:
                return n
        configured = [n for n in nets if n.configured]
        return configured[0] if configured else None

    def process(self, ev: Event, ctx: DetectionContext) -> list[Finding]:
        if not self.cfg.enabled or ev.event_type not in AP_OBSERVATION_TYPES or not ev.ssid or not ev.bssid:
            return []
        net = self._network(ev, ctx)
        if net is None:
            return []  # not protected, or unconfigured (no BSSID registered): nothing is adopted
        update = ctx.last_ap_update if ctx.last_ap_update and ctx.last_ap_update[0].bssid == ev.bssid else None
        current, prev = (update if update else (None, None))
        authorized = ev.bssid in net.bssids
        sec = ev.security
        issues: dict[str, list[str]] = {}
        details: dict = {"authorized": authorized, "observed": sec.to_dict() if sec else None}
        out: list[Finding] = []

        # 1) registry expectations
        if sec is not None:
            want = expected_rank(net.security.expected)
            if (want is not None and sec.rank < want) or (
                    "WPA3" in net.security.expected and "WPA3" not in sec.protocols):
                issues.setdefault("security_downgrade", []).append(
                    f"registry expects {'/'.join(net.security.expected)}")
            if net.security.pmf and sec.pmf_rank < PMF_LEVELS.index(net.security.pmf):
                issues.setdefault("pmf_downgrade", []).append(f"registry expects PMF {net.security.pmf}")

        if authorized:
            # 2) changes on a registered BSSID
            before = prev.security if prev is not None else (
                ctx.baseline.security_for(net.name, ev.bssid) if ctx.baseline is not None else None)
            if sec is not None and before is not None and not sec.same_capabilities(before):
                recent = [t for t, _ in current.history if ev.timestamp - t <= FLAP_WINDOW] if current else []
                details.update({"from": before.to_dict(), "bssid_conflict": len(recent) >= FLAP_CHANGES})
                pmf_lost = sec.pmf_rank < before.pmf_rank
                if _downgraded(sec, before):
                    issues.setdefault("security_downgrade", []).append(f"was {before.mode}")
                elif not pmf_lost:
                    issues.setdefault("encryption_change", []).append(f"was {describe(before)}")
                if pmf_lost:
                    issues.setdefault("pmf_downgrade", []).append(f"was PMF {before.pmf}")
                if details["bssid_conflict"]:
                    issues.setdefault("security_downgrade", []).append(
                        "alternating profiles on one BSSID: possible cloned BSSID")
            if self.cfg.channel_anomaly and ev.channel:
                if net.channels and ev.channel not in net.channels:
                    issues.setdefault("channel_anomaly", []).append(
                        f"registered BSSID on channel {ev.channel}, registry lists "
                        f"{','.join(map(str, net.channels))}")
                elif not net.channels:
                    known = ctx.baseline.channels_for(ev.bssid) if ctx.baseline else set()
                    if known and ev.channel not in known:
                        issues.setdefault("channel_anomaly", []).append(
                            f"channel {ev.channel} not seen in baseline ({','.join(map(str, sorted(known)))})")
                    elif prev is not None and prev.channel and prev.channel != ev.channel:
                        issues.setdefault("channel_anomaly", []).append(f"channel {prev.channel} -> {ev.channel}")
        else:
            # 3) unknown BSSID for the protected SSID
            similar = _similar(ev.bssid, net.bssids)
            if self._once(("unknown", net.name, ev.bssid), ev.timestamp):
                out.append(finding(
                    UNKNOWN_BSSID, ev, ctx, category="unknown_bssid", label="unknown BSSID for protected SSID",
                    detail=f"{ev.bssid} advertises '{ev.ssid}' on channel {ev.channel or '?'} ({describe(sec)})",
                    network=net,
                    details={"authorized": False, "bssid": ev.bssid, "channel": ev.channel,
                             "security": sec.to_dict() if sec else None, "similar_to": similar,
                             "frame": ev.event_type.value, "hint": self._register_hint(net, ev.bssid, ctx)}))
            ref = self._reference(net, ctx)
            if sec is not None and ref is not None:
                details["reference"] = ref.to_dict()
                if _downgraded(sec, ref):
                    issues.setdefault("security_downgrade", []).append(f"registered AP advertises {ref.mode}")
                if sec.pmf_rank < ref.pmf_rank:
                    issues.setdefault("pmf_downgrade", []).append(f"registered AP has PMF {ref.pmf}")
                if not (sec.protocols & ref.protocols) or sec.has_enterprise != ref.has_enterprise:
                    issues.setdefault("incompatible_duplicate", []).append(f"registered AP: {ref.mode}")
            if self.cfg.channel_anomaly and ev.channel and net.channels and ev.channel not in net.channels:
                issues.setdefault("channel_anomaly", []).append(
                    f"unknown BSSID on channel {ev.channel}, protected network uses "
                    f"{','.join(map(str, net.channels))}")

        signature = sec.signature() if sec is not None else None
        for category, reasons in issues.items():
            key = (category, ev.bssid, signature if category != "channel_anomaly" else ev.channel,
                   details.get("bssid_conflict", False))
            if not self._once(key, ev.timestamp):
                continue
            ftype, label = _CATEGORY[category]
            what = ("PMF " + sec.pmf) if category == "pmf_downgrade" and sec else (sec.mode if sec else "")
            detail = "; ".join(reasons) if category == "channel_anomaly" else f"{what} advertised ({'; '.join(reasons)})"
            out.append(finding(ftype, ev, ctx, category=category, label=label, detail=detail,
                               network=net, details=dict(details)))
        return out
