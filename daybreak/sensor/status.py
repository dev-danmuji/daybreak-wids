"""Sensor health: detects the ALFA adapter disappearing and coming back.

A MediaTek USB adapter can drop off the bus (unplug, firmware crash, USB
reset). The interface then vanishes from sysfs and usually re-appears with the
same MAC (and, for ``wlx<mac>`` names, the same name).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class SensorState(str, enum.Enum):
    UNKNOWN = "UNKNOWN"
    ONLINE = "ONLINE"
    LOST = "LOST"


@dataclass
class HealthTransition:
    status: str                 # SENSOR_LOST | SENSOR_RECOVERED
    timestamp: float
    interface: str
    mac: str | None
    previous_interface: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


class SensorHealthMonitor:
    def __init__(self, interface: str, *, expected_mac: str | None = None,
                 sysfs_root: str | Path = "/sys/class/net"):
        self.interface = interface
        self.sysfs_root = Path(sysfs_root)
        self.expected_mac = expected_mac.upper() if expected_mac else None
        self.state = SensorState.UNKNOWN
        self.lost_at: float | None = None
        self.lost_count = 0

    def _mac_of(self, iface: str) -> str | None:
        try:
            return (self.sysfs_root / iface / "address").read_text().strip().upper()
        except OSError:
            return None

    def _is_wireless(self, iface: str) -> bool:
        return (self.sysfs_root / iface / "phy80211").exists()

    def locate(self) -> tuple[str | None, str | None]:
        """Return (interface, mac) of the sensor if present, else (None, None)."""
        if self._is_wireless(self.interface):
            mac = self._mac_of(self.interface)
            if self.expected_mac is None or mac == self.expected_mac:
                return self.interface, mac
        if self.expected_mac and self.sysfs_root.is_dir():
            for entry in sorted(self.sysfs_root.iterdir(), key=lambda p: p.name):
                if self._is_wireless(entry.name) and self._mac_of(entry.name) == self.expected_mac:
                    return entry.name, self.expected_mac
        return None, None

    def check(self, now: float) -> HealthTransition | None:
        iface, mac = self.locate()
        if iface is not None:
            if self.expected_mac is None and mac:
                self.expected_mac = mac  # learn the adapter MAC on first sight
            if self.state is SensorState.LOST:
                previous = self.interface
                self.interface = iface
                self.state = SensorState.ONLINE
                down_for = now - self.lost_at if self.lost_at else None
                self.lost_at = None
                return HealthTransition("SENSOR_RECOVERED", now, iface, mac, previous_interface=previous,
                                        details={"offline_seconds": round(down_for, 1) if down_for else None,
                                                 "renamed": previous != iface})
            self.interface = iface
            self.state = SensorState.ONLINE
            return None
        if self.state is not SensorState.LOST:
            was_unknown = self.state is SensorState.UNKNOWN
            self.state = SensorState.LOST
            self.lost_at = now
            self.lost_count += 1
            return HealthTransition("SENSOR_LOST", now, self.interface, self.expected_mac,
                                    details={"at_startup": was_unknown,
                                             "hint": usb_hint()})
        return None


def usb_hint() -> str:
    return ("check the USB connection (`lsusb | grep -i 0e8d`) and `dmesg | grep -i mt7921`; "
            "monitoring resumes automatically when the adapter returns")
