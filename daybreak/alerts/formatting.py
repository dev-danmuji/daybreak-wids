"""Human-readable alert rendering (log file and console)."""

from __future__ import annotations

from ..models import Alert, format_local
from ..scoring import explain


def human_lines(alert: Alert) -> list[str]:
    lines = [f"{format_local(alert.timestamp)} {alert.severity.name} {alert.alert_type}"]
    if alert.network or alert.ssid:
        lines.append(f"Network={alert.network or '-'} SSID={alert.ssid or '-'}")
    if alert.bssid:
        lines.append(f"BSSID={alert.bssid}")
    if alert.channel:
        lines.append(f"Channel={alert.channel}")
    d = alert.details
    if "frames" in d and "window" in d:
        lines.append(f"Frames={d['frames']}/{float(d['window']):g}s")
    if d.get("affected_stations"):
        lines.append(f"AffectedStations={d['affected_stations']}")
    elif alert.stations:
        lines.append(f"Stations={len(alert.stations)}")
    if d.get("reauthenticated_stations"):
        lines.append(f"ReauthenticatedStations={d['reauthenticated_stations']}")
    if d.get("rogue_bssids"):
        lines.append(f"RogueBSSIDs={','.join(d['rogue_bssids'])}")
    if alert.sensor:
        lines.append(f"Sensor={alert.sensor}")
    lines += explain(alert.score, alert.components)
    if alert.summary:
        lines.append(f"Summary={alert.summary}")
    if d.get("hint"):
        lines.append(f"Hint={d['hint']}")
    if alert.suppressed_count:
        lines.append(f"Suppressed={alert.suppressed_count} similar alert(s) since the previous one")
    return lines


def human_text(alert: Alert) -> str:
    return "\n".join(human_lines(alert))
