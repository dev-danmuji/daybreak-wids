"""Notifier interface and registry.

To add a channel (Slack, Discord, Telegram, e-mail, webhook, ...), subclass
:class:`Notifier`, implement :meth:`notify`, and register it::

    @register_notifier("webhook")
    class WebhookNotifier(Notifier):
        def __init__(self, min_severity="HIGH", url="", **options):
            super().__init__(min_severity, **options)
            self.url = url

        def notify(self, alert):
            ...  # POST alert.to_dict() to self.url

and enable it in ``alerts.notifiers`` with ``type: webhook`` and its options.
Notifiers receive alert metadata only (never frames or key material).
"""

from __future__ import annotations

import abc
from typing import Any, Callable

from ..models import Alert, Severity

NOTIFIER_TYPES: dict[str, type["Notifier"]] = {}


def register_notifier(name: str) -> Callable[[type["Notifier"]], type["Notifier"]]:
    def deco(cls: type["Notifier"]) -> type["Notifier"]:
        cls.type_name = name
        NOTIFIER_TYPES[name] = cls
        return cls
    return deco


class Notifier(abc.ABC):
    type_name = "base"
    # Human-facing channels are rate limited; record-keeping ones (JSONL) are not.
    rate_limited = True

    def __init__(self, min_severity: Any = "LOW", **options: Any):
        self.min_severity = Severity.parse(min_severity)
        self.options = options
        self.errors = 0
        self.last_error: str | None = None

    def accepts(self, alert: Alert) -> bool:
        return alert.severity >= self.min_severity

    @abc.abstractmethod
    def notify(self, alert: Alert, *, note: str | None = None) -> None:
        """Deliver one alert. ``note`` carries e.g. rate-limit information."""

    def close(self) -> None:
        pass


def build_notifiers(configs: list[Any], **context: Any) -> list[Notifier]:
    """Instantiate notifiers from ``alerts.notifiers`` config entries."""
    from . import console, desktop, jsonl  # noqa: F401  (registration side effects)

    out = []
    for nc in configs:
        cls = NOTIFIER_TYPES.get(nc.type)
        if cls is None:
            raise ValueError(f"unknown notifier type {nc.type!r} (available: {', '.join(sorted(NOTIFIER_TYPES))})")
        out.append(cls(min_severity=nc.min_severity, **{**context.get(nc.type, {}), **nc.options}))
    return out
