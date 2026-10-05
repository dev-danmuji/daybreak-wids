"""Console notifier."""

from __future__ import annotations

import sys
from typing import Any, TextIO

from ..models import Alert, Severity
from .base import Notifier, register_notifier
from .formatting import human_lines

_COLORS = {
    Severity.INFO: "\033[37m", Severity.LOW: "\033[36m", Severity.MEDIUM: "\033[33m",
    Severity.HIGH: "\033[31m", Severity.CRITICAL: "\033[1;41;97m",
}
_RESET = "\033[0m"


@register_notifier("console")
class ConsoleNotifier(Notifier):
    CONFIG_OPTIONS = frozenset({"color"})
    def __init__(self, min_severity: Any = "LOW", stream: TextIO | None = None, color: bool | None = None,
                 **options: Any):
        super().__init__(min_severity, **options)
        self.stream = stream or sys.stdout
        self.color = self.stream.isatty() if color is None and hasattr(self.stream, "isatty") else bool(color)

    def notify(self, alert: Alert, *, note: str | None = None) -> None:
        lines = human_lines(alert)
        if self.color:
            lines[0] = f"{_COLORS[alert.severity]}{lines[0]}{_RESET}"
        if note:
            lines.append(f"({note})")
        self.stream.write("\n".join(lines) + "\n\n")
        self.stream.flush()
