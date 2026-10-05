"""Desktop notifications via ``notify-send`` (freedesktop.org)."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any, Callable

from ..models import Alert, Severity
from .base import Notifier, register_notifier

_URGENCY = {Severity.INFO: "low", Severity.LOW: "low", Severity.MEDIUM: "normal",
            Severity.HIGH: "critical", Severity.CRITICAL: "critical"}


def desktop_available() -> tuple[bool, str]:
    if shutil.which("notify-send") is None:
        return False, "notify-send not installed (package libnotify-bin)"
    if not (os.environ.get("DBUS_SESSION_BUS_ADDRESS") or os.environ.get("DISPLAY")
            or os.environ.get("WAYLAND_DISPLAY")):
        return False, "no desktop session (running as root/service?) - desktop notifications disabled"
    return True, ""


@register_notifier("desktop")
class DesktopNotifier(Notifier):
    def __init__(self, min_severity: Any = "HIGH", run: Callable[..., Any] | None = None,
                 available: bool | None = None, **options: Any):
        super().__init__(min_severity, **options)
        self._run = run or subprocess.run
        if available is None:
            available, why = desktop_available()
            self.disabled_reason = None if available else why
        else:
            self.disabled_reason = None if available else "disabled"
        self.enabled = bool(available)

    def notify(self, alert: Alert, *, note: str | None = None) -> None:
        if not self.enabled:
            return
        title = f"daybreak-wids: {alert.severity.name} {alert.alert_type}"
        where = " ".join(x for x in (alert.network and f"network {alert.network}",
                                     alert.bssid and f"BSSID {alert.bssid}") if x)
        body = f"Risk {alert.score}. {alert.summary}" + (f"\n{where}" if where else "")
        if note:
            body += f"\n({note})"
        try:
            self._run(["notify-send", "--app-name=daybreak-wids", f"--urgency={_URGENCY[alert.severity]}",
                       title, body[:500]], check=False, timeout=5, capture_output=True)
        except (OSError, subprocess.SubprocessError) as exc:
            self.errors += 1
            self.last_error = str(exc)
