"""Passive WPA / PMF configuration audit for protected networks.

Works purely from advertised capabilities (beacons / probe responses, or
Kismet AP records). It never changes AP settings; it only reports and
recommends.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from ..config import ProtectedNetwork
from ..models import SecurityProfile, format_local

OK, INFO, WARN, RISK = "ok", "info", "warn", "risk"
_ORDER = {RISK: 0, WARN: 1, INFO: 2, OK: 3}


@dataclass
class AuditItem:
    level: str
    title: str
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"level": self.level, "title": self.title, "detail": self.detail}


@dataclass
class APObservation:
    bssid: str
    profile: SecurityProfile | None
    channel: int | None = None
    last_seen: float | None = None
    authorized: bool | None = None


@dataclass
class NetworkAudit:
    network: str
    ssid: str
    status: str
    aps: list[APObservation] = field(default_factory=list)
    unknown: list[APObservation] = field(default_factory=list)
    items: list[AuditItem] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def profile(self) -> SecurityProfile | None:
        """Weakest advertised profile among registered BSSIDs (what an attacker would target)."""
        profiles = [a.profile for a in self.aps if a.profile is not None]
        return min(profiles, key=lambda p: (p.rank, p.pmf_rank)) if profiles else None

    @property
    def worst_level(self) -> str:
        return min((i.level for i in self.items), key=lambda lv: _ORDER[lv], default=OK)

    def to_dict(self) -> dict[str, Any]:
        prof = self.profile
        return {
            "network": self.network, "ssid": self.ssid, "status": self.status,
            "mode": prof.mode if prof else None,
            "transition_mode": prof.transition_mode if prof else None,
            "pmf": prof.pmf if prof else None,
            "pmf_required": prof.mfp_required if prof else None,
            "wps": prof.wps if prof else None,
            "aps": [{"bssid": a.bssid, "channel": a.channel, "mode": a.profile.mode if a.profile else None,
                     "pmf": a.profile.pmf if a.profile else None, "last_seen": a.last_seen} for a in self.aps],
            "unknown_bssids": [a.bssid for a in self.unknown],
            "items": [i.to_dict() for i in self.items],
            "recommendations": list(self.recommendations),
            "worst_level": self.worst_level,
        }


def assess_profile(p: SecurityProfile) -> tuple[list[AuditItem], list[str]]:
    """Return (findings, recommendations) for one advertised security profile."""
    items: list[AuditItem] = []
    recs: list[str] = []
    mode = p.mode
    if mode == "OPEN":
        items.append(AuditItem(RISK, "no encryption", "traffic and credentials of clients are exposed"))
        recs.append("Enable WPA3-SAE (or WPA2/WPA3 transition while old clients remain); "
                    "for public guest access use OWE (Enhanced Open).")
    elif mode == "WEP":
        items.append(AuditItem(RISK, "WEP", "WEP is broken and recoverable within minutes"))
        recs.append("Replace WEP with WPA3-SAE (or WPA2/WPA3 transition).")
    elif mode in ("WPA", "WPA/WPA2-MIXED"):
        items.append(AuditItem(RISK, "WPA (TKIP) enabled", "legacy WPA/TKIP is deprecated"))
        recs.append("Disable WPA/TKIP; use WPA3-SAE, or WPA2-CCMP only if some clients lack WPA3.")
    elif mode == "WPA2-PSK":
        items.append(AuditItem(WARN, "WPA2-PSK only",
                               "a captured 4-way handshake allows offline dictionary attacks against "
                               "weak passphrases"))
        recs.append("Enable WPA3-SAE (transition mode first if some clients are WPA2-only).")
    elif mode == "WPA2/WPA3-TRANSITION":
        items.append(AuditItem(INFO, "WPA2/WPA3 transition mode",
                               "WPA2-PSK remains available, so clients can still be steered to the "
                               "weaker method"))
        recs.append("Consider WPA3-SAE + PMF required if every client supports it.")
    elif mode == "WPA3-SAE":
        items.append(AuditItem(OK, "WPA3-SAE", "resistant to offline dictionary attacks"))
    elif mode in ("WPA2-ENTERPRISE", "WPA3-ENTERPRISE"):
        items.append(AuditItem(OK if mode == "WPA3-ENTERPRISE" else INFO, mode,
                               "802.1X: credential strength depends on the RADIUS/EAP setup"))
        if mode == "WPA2-ENTERPRISE":
            recs.append("Verify clients validate the RADIUS server certificate; consider WPA3-Enterprise.")
    elif mode == "OWE":
        items.append(AuditItem(INFO, "OWE (Enhanced Open)", "encrypted but unauthenticated"))

    if p.weak_ciphers and mode not in ("WEP",):
        items.append(AuditItem(RISK, "weak cipher", ", ".join(p.weak_ciphers)))
        recs.append("Allow only CCMP (AES) / GCMP ciphers; disable TKIP.")

    if mode not in ("OPEN", "WEP"):
        if p.pmf == "disabled":
            items.append(AuditItem(WARN, "PMF disabled",
                                   "management frames are unprotected: spoofed deauthentication / "
                                   "disassociation can disconnect clients"))
            recs.append("Enable Protected Management Frames (802.11w): at least 'optional/capable', "
                        "'required' where all clients support it.")
        elif p.pmf == "capable":
            items.append(AuditItem(INFO, "PMF capable (optional)",
                                   "clients that do not negotiate PMF can still be disconnected by "
                                   "spoofed frames"))
            if "Consider WPA3-SAE + PMF required if every client supports it." not in recs:
                recs.append("Set PMF to 'required' if every client supports it.")
        else:
            items.append(AuditItem(OK, "PMF required", "spoofed deauth/disassoc frames are ignored by clients"))
        if mode == "WPA3-SAE" and p.pmf != "required":
            items.append(AuditItem(WARN, "WPA3 without PMF required",
                                   "WPA3-Personal-only networks must require PMF"))
        if p.has_sae and p.sae_h2e is False:
            items.append(AuditItem(INFO, "SAE hash-to-element not advertised",
                                   "H2E hardens SAE against side channels and is mandatory on 6 GHz"))
            recs.append("Enable SAE hash-to-element (H2E), e.g. sae_pwe=2, if the AP firmware supports it.")

    if p.wps:
        items.append(AuditItem(WARN, "WPS advertised", "WPS PIN/push-button provisioning is enabled"))
        recs.append("Disable WPS on the router.")
    return items, recs


def audit_network(net: ProtectedNetwork, observations: Iterable[APObservation]) -> NetworkAudit:
    obs = list(observations)
    audit = NetworkAudit(network=net.name, ssid=net.ssid, status=net.status)
    if net.configured:
        audit.aps = [o for o in obs if o.bssid in net.bssids]
        audit.unknown = [o for o in obs if o.bssid not in net.bssids]
    else:
        audit.unknown = obs  # candidates only: never adopted automatically
    if not net.configured:
        audit.items.append(AuditItem(INFO, "unconfigured",
                                     "no BSSID registered; observed BSSIDs are listed as candidates only"))
    if not audit.aps:
        if net.configured:
            audit.items.append(AuditItem(INFO, "not observed",
                                         "no beacon from a registered BSSID has been recorded yet"))
        return audit
    seen_titles: set[str] = set()
    for ap in audit.aps:
        if ap.profile is None:
            continue
        items, recs = assess_profile(ap.profile)
        for item in items:
            key = (item.level, item.title)
            if key not in seen_titles:
                seen_titles.add(key)
                audit.items.append(item)
        for r in recs:
            if r not in audit.recommendations:
                audit.recommendations.append(r)
    modes = {ap.profile.signature() for ap in audit.aps if ap.profile is not None}
    if len(modes) > 1:
        audit.items.append(AuditItem(WARN, "inconsistent security across BSSIDs",
                                     "registered radios advertise different security settings"))
        audit.recommendations.append("Use the same security settings on every radio/BSSID of the network.")
    if net.security.expected:
        prof = audit.profile
        if prof is not None and not set(net.security.expected) >= set(prof.protocols) - {"OWE"}:
            audit.items.append(AuditItem(WARN, "differs from registry expectation",
                                         f"advertised {prof.mode}, expected {'/'.join(net.security.expected)}"))
    if audit.unknown:
        audit.items.append(AuditItem(WARN, "unregistered BSSIDs advertise this SSID",
                                     ", ".join(sorted(o.bssid for o in audit.unknown))))
    audit.items.sort(key=lambda i: _ORDER[i.level])
    return audit


def observations_from_rows(rows: Iterable[Mapping[str, Any]]) -> list[APObservation]:
    """Convert ``aps`` table rows into observations."""
    out = []
    for r in rows:
        sec = r.get("security")
        try:
            profile = SecurityProfile.from_dict(sec) if isinstance(sec, Mapping) else None
        except ValueError:
            profile = None
        auth = r.get("authorized")
        out.append(APObservation(bssid=r["bssid"], profile=profile, channel=r.get("channel"),
                                 last_seen=r.get("last_seen"), authorized=None if auth is None else bool(auth)))
    return out


def render_audit(audit: NetworkAudit) -> str:
    lines = [f"SSID: {audit.ssid}  (network '{audit.network}', {audit.status})", ""]
    prof = audit.profile
    if prof is None:
        lines.append("Security             : not observed yet")
    else:
        lines += [
            f"Security             : {prof.mode}",
            f"WPA2/WPA3 Transition : {'enabled' if prof.transition_mode else 'no'}",
            f"PMF                  : {prof.pmf}",
            f"PMF required         : {'yes' if prof.mfp_required else 'no'}",
            f"WPS advertised       : {'yes' if prof.wps else ('no' if prof.source == 'ie' else 'unknown')}",
        ]
    for ap in audit.aps:
        seen = format_local(ap.last_seen) if ap.last_seen else "-"
        mode = ap.profile.mode if ap.profile else "?"
        lines.append(f"  {ap.bssid}  ch {ap.channel or '?':>3}  {mode:<22} last seen {seen}")
    if audit.unknown:
        label = "Candidates (unregistered)" if audit.status == "unconfigured" else "Unregistered BSSIDs"
        lines.append(f"{label}:")
        for ap in audit.unknown:
            mode = ap.profile.mode if ap.profile else "?"
            lines.append(f"  {ap.bssid}  ch {ap.channel or '?':>3}  {mode}")
    if audit.items:
        lines += ["", "Findings:"]
        for item in audit.items:
            lines.append(f"  [{item.level.upper():<4}] {item.title}" + (f" - {item.detail}" if item.detail else ""))
    if audit.recommendations:
        lines += ["", "Recommendation:"]
        lines += [f"  {r}" for r in audit.recommendations]
    lines.append("")
    lines.append("(daybreak-wids never changes AP settings; apply changes on the router yourself.)")
    return "\n".join(lines)
