"""Human-readable alert rendering (log file and console)."""

from __future__ import annotations

import unicodedata

from ..models import Alert, format_local
from ..scoring import explain

# Control and format characters, line/paragraph separators and lone surrogates (Unicode
# categories Cc, Cf, Zl, Zp, Cs): an attacker-chosen SSID or a relayed Kismet alert text must
# not move the cursor, forge log lines, reorder what is shown or hide text.
_ESCAPED = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})


def _escape(ch: str) -> str:
    if unicodedata.category(ch) not in _ESCAPED:
        return ch
    c = ord(ch)
    return f"\\x{c:02x}" if c < 0x100 else f"\\u{c:04x}" if c < 0x10000 else f"\\U{c:08x}"


def printable(text: object) -> str:
    """``text`` with those characters shown as ``\\xNN`` / ``\\uNNNN`` / ``\\UNNNNNNNN`` escapes."""
    s = str(text)
    if s.isascii() and s.isprintable():
        return s
    return "".join(_escape(ch) for ch in s)


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
