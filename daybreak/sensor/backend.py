"""Capture backend interface. Backends only *receive*; none can transmit."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from ..models import Event


class BackendUnavailable(RuntimeError):
    """The backend cannot deliver events right now (retry later)."""


@dataclass
class BackendStatus:
    name: str
    healthy: bool
    detail: str = ""
    sensor_ok: bool | None = None       # None: backend cannot tell
    extra: dict[str, Any] = field(default_factory=dict)


class Backend(abc.ABC):
    name = "base"

    def __init__(self, sensor_name: str = ""):
        self.sensor_name = sensor_name
        self.stats: dict[str, int] = {"events": 0, "malformed": 0}
        self.errors: list[str] = []

    def open(self) -> None:  # pragma: no cover - default no-op
        pass

    def close(self) -> None:  # pragma: no cover - default no-op
        pass

    @abc.abstractmethod
    def poll(self, timeout: float) -> list[Event]:
        """Return the events available now, waiting at most ``timeout`` seconds."""

    @property
    def finished(self) -> bool:
        """True once a finite source (replay/pcap) is exhausted."""
        return False

    def status(self) -> BackendStatus:
        return BackendStatus(self.name, True)

    def set_interface(self, interface: str) -> None:
        """Called when the sensor re-appears under a different interface name."""

    def note_error(self, message: str, limit: int = 20) -> None:
        self.errors.append(message)
        del self.errors[:-limit]
