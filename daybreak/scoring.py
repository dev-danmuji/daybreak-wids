"""Risk score helpers shared by reports, CLI and dashboard.

Scores are additive: every alert lists the components that produced it and
``score == min(100, sum(components))``. Bands: 0-29 INFO, 30-49 LOW,
50-69 MEDIUM, 70-89 HIGH, 90-100 CRITICAL.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from .models import Severity

THREAT_LEVELS = ("NORMAL", "ELEVATED", "HIGH", "CRITICAL")


def severity_of(alert: Any) -> Severity:
    if isinstance(alert, Mapping):
        return Severity.parse(alert.get("severity", "INFO"))
    return alert.severity


def threat_level(alerts: Iterable[Any]) -> str:
    """Overall level from recent alerts: NORMAL / ELEVATED / HIGH / CRITICAL."""
    worst = max((severity_of(a) for a in alerts), default=Severity.INFO)
    if worst >= Severity.CRITICAL:
        return "CRITICAL"
    if worst >= Severity.HIGH:
        return "HIGH"
    if worst >= Severity.LOW:
        return "ELEVATED"
    return "NORMAL"


def explain(score: int, components: Iterable[Any]) -> list[str]:
    """``Risk 82 HIGH`` followed by one ``+N label (detail)`` line per component."""
    lines = [f"Risk {score} {Severity.from_score(score).name}"]
    for c in components:
        if isinstance(c, Mapping):
            pts, label, detail = c.get("points", 0), c.get("label", ""), c.get("detail", "")
        else:
            pts, label, detail = c.points, c.label, c.detail
        sign = "+" if pts >= 0 else ""
        lines.append(f"{sign}{pts} {label}" + (f" ({detail})" if detail else ""))
    return lines
