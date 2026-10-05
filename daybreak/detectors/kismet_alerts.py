"""Turn Kismet WIDS alerts into weighted findings (no re-implementation).

A Kismet alert and the equivalent daybreak-wids observation share a scoring
category, so the correlator counts the phenomenon once and cites both sources.
"""

from __future__ import annotations

from ..models import Event, EventType, Finding
from .base import DetectionContext, finding

# header -> (category / weight key, label)
KISMET_ALERT_MAP: dict[str, tuple[str, str]] = {
    "DEAUTHFLOOD": ("deauth_burst", "deauth flood (Kismet DEAUTHFLOOD)"),
    "BCASTDISCON": ("broadcast_deauth", "broadcast disconnect (Kismet BCASTDISCON)"),
    "DISASSOCTRAFFIC": ("suspicious_source", "traffic after disassociation (Kismet DISASSOCTRAFFIC)"),
    "DISCONCODEINVALID": ("invalid_reason_code", "invalid disconnect reason (Kismet DISCONCODEINVALID)"),
    "DEAUTHCODEINVALID": ("invalid_reason_code", "invalid deauth reason (Kismet DEAUTHCODEINVALID)"),
    "APSPOOF": ("unknown_bssid", "unauthorized BSSID for SSID (Kismet APSPOOF)"),
    "ADVCRYPTCHANGE": ("encryption_change", "advertised encryption changed (Kismet ADVCRYPTCHANGE)"),
    "CRYPTODROP": ("security_downgrade", "encryption dropped (Kismet CRYPTODROP)"),
    "CHANCHANGE": ("channel_anomaly", "channel change (Kismet CHANCHANGE)"),
}
INFORMATIONAL = {"NOCLIENTMFP"}


class KismetAlertDetector:
    name = "kismet"

    def process(self, ev: Event, ctx: DetectionContext) -> list[Finding]:
        if ev.event_type is not EventType.KISMET_ALERT:
            return []
        header = str(ev.metadata.get("kismet_header", "")).upper()
        if not header:
            return []
        text = str(ev.metadata.get("kismet_text", ""))
        if header in KISMET_ALERT_MAP:
            category, label = KISMET_ALERT_MAP[header]
            points = None
        elif header in INFORMATIONAL:
            category, label, points = "kismet_info", f"Kismet {header}", 0
        else:
            category, label, points = "kismet_other", f"Kismet {header}", None
        stations = {ev.station} if ev.station else set()
        return [finding(
            f"KISMET_{header}", ev, ctx, category=category, label=label, detail=text[:160],
            stations=stations, points=points,
            details={"kismet_header": header, "kismet_text": text, "kismet_class": ev.metadata.get("kismet_class"),
                     "authorized": (ev.bssid in ctx.registry.protected_bssids) if ev.bssid else None},
        )]
