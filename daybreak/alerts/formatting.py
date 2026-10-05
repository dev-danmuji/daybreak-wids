"""Human-readable alert rendering (log file and console)."""

from __future__ import annotations

import re

from ..models import Alert, format_local
from ..scoring import explain

# C0/C1 control characters and Unicode bidi overrides: an attacker-chosen SSID or a relayed
# Kismet alert text must not move the cursor, forge log lines or reorder what is shown.
_UNPRINTABLE = re.compile("[\x00-\x1f\x7f-\x9f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def printable(text: object) -> str:
    """``text`` with control characters shown as ``\\xNN`` / ``\\uNNNN`` escapes."""
    def esc(m: re.Match) -> str:
        c = ord(m.group())
        return f"\\x{c:02x}" if c < 0x100 else f"\\u{c:04x}"
    return _UNPRINTABLE.sub(esc, str(text))


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
        more = int(d.get("rogue_bssid_count") or 0) - len(d["rogue_bssids"])
        lines.append(f"RogueBSSIDs={','.join(d['rogue_bssids'])}" + (f" (+{more} more)" if more > 0 else ""))
    if alert.sensor:
        lines.append(f"Sensor={alert.sensor}")
    lines += explain(alert.score, alert.components)
    if alert.summary:
        lines.append(f"Summary={alert.summary}")
    if d.get("hint"):
        lines.append(f"Hint={d['hint']}")
    if alert.suppressed_count:
        lines.append(f"Suppressed={alert.suppressed_count} similar alert(s) since the previous one")
    return [printable(line) for line in lines]


def human_text(alert: Alert) -> str:
    return "\n".join(human_lines(alert))
