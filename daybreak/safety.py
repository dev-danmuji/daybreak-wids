"""Passive-only safety model.

daybreak-wids never transmits. There is no injection, deauthentication,
handshake capture/export, cracking or password-guessing code anywhere in this
package; ``tests/test_safety.py`` enforces that statically.

This module covers the remaining risk: changing the *wrong* network interface.
Only the dedicated sensor interface may ever be reconfigured (monitor mode,
channel). Interfaces listed in ``sensor.protected_interfaces`` (``wlo1`` by
default), any interface that carries the default route, and any interface that
shares a PHY with one of those are off-limits, and their state is snapshotted
before and verified after every sensor operation.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence


class SafetyViolation(RuntimeError):
    """Raised when an operation would break the passive-only guarantees."""


REQUIRED_SAFETY = {
    "passive_only": True,
    "packet_injection": False,
    "transmit_management_frames": False,
}


def enforce_passive(safety: Any) -> None:
    """Refuse any configuration that is not strictly passive.

    These flags are declarations, not switches: no transmit path exists, so the
    only valid values are the passive ones.
    """
    for key, required in REQUIRED_SAFETY.items():
        value = getattr(safety, key) if not isinstance(safety, Mapping) else safety.get(key, required)
        if value is not required:
            raise SafetyViolation(
                f"safety.{key} must be {str(required).lower()}: daybreak-wids is a "
                "passive monitoring tool and has no transmit or injection capability"
            )


# ---------------------------------------------------------------------------
# Command execution (all sensor changes go through here)
# ---------------------------------------------------------------------------


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandRunner:
    """Runs read-only inspection commands and guarded sensor commands."""

    def __init__(self, dry_run: bool = False, timeout: float = 10.0):
        self.dry_run = dry_run
        self.timeout = timeout
        self.history: list[list[str]] = []

    def run(self, argv: Sequence[str], *, mutating: bool = False) -> CommandResult:
        argv = list(argv)
        self.history.append(argv)
        if mutating and self.dry_run:
            return CommandResult(argv, 0, "", "dry-run: not executed")
        env = dict(os.environ, LC_ALL="C", LANG="C")
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=self.timeout,
                                  env=env, check=False)
        except FileNotFoundError:
            return CommandResult(argv, 127, "", f"{argv[0]}: command not found")
        except subprocess.TimeoutExpired:
            return CommandResult(argv, 124, "", f"{argv[0]}: timed out")
        return CommandResult(argv, proc.returncode, proc.stdout, proc.stderr)


# ---------------------------------------------------------------------------
# Interface guard
# ---------------------------------------------------------------------------


def default_route_interfaces(route_file: str | Path = "/proc/net/route") -> set[str]:
    """Interfaces that currently carry an IPv4 or IPv6 default route."""
    out: set[str] = set()
    try:
        with open(route_file, encoding="ascii") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    out.add(parts[0])
    except OSError:
        pass
    ipv6 = Path(route_file).with_name("ipv6_route")
    try:
        with open(ipv6, encoding="ascii") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 10 and parts[0] == "0" * 32 and parts[1] == "00" and parts[9] != "lo":
                    out.add(parts[9])
    except OSError:
        pass
    return out


@dataclass
class InterfaceSnapshot:
    name: str
    exists: bool
    operstate: str | None = None
    mac: str | None = None
    phy: str | None = None
    iftype: str | None = None
    ssid: str | None = None
    channel: str | None = None
    nm_state: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def compare(self, after: "InterfaceSnapshot") -> list[str]:
        """Return human-readable differences (empty list == unchanged)."""
        diffs = []
        for name in ("exists", "operstate", "mac", "iftype", "ssid", "nm_state"):
            before_v, after_v = getattr(self, name), getattr(after, name)
            if before_v != after_v:
                diffs.append(f"{name}: {before_v!r} -> {after_v!r}")
        return diffs


class InterfaceGuard:
    """Decides which interfaces may be touched and verifies the rest are not."""

    def __init__(
        self,
        protected_interfaces: Iterable[str],
        *,
        sysfs_root: str | Path = "/sys/class/net",
        route_file: str | Path = "/proc/net/route",
        runner: CommandRunner | None = None,
        nm_state_lookup: Callable[[str], str | None] | None = None,
    ):
        self.configured = [i for i in protected_interfaces if i]
        self.sysfs_root = Path(sysfs_root)
        self.route_file = Path(route_file)
        self.runner = runner or CommandRunner()
        self._nm_state_lookup = nm_state_lookup

    # -- sysfs helpers -----------------------------------------------------
    def _read(self, iface: str, rel: str) -> str | None:
        try:
            return (self.sysfs_root / iface / rel).read_text().strip()
        except OSError:
            return None

    def phy_of(self, iface: str) -> str | None:
        phy_link = self.sysfs_root / iface / "phy80211"
        try:
            return os.path.basename(os.path.realpath(phy_link)) if phy_link.exists() else None
        except OSError:
            return None

    def protected_set(self) -> set[str]:
        """Configured protected interfaces + default-route interfaces + PHY siblings."""
        protected = set(self.configured) | default_route_interfaces(self.route_file)
        phys = {p for p in (self.phy_of(i) for i in protected) if p}
        if phys and self.sysfs_root.is_dir():
            for entry in self.sysfs_root.iterdir():
                if self.phy_of(entry.name) in phys:
                    protected.add(entry.name)
        return protected

    def assert_may_modify(self, iface: str) -> None:
        """Raise :class:`SafetyViolation` unless ``iface`` is a safe sensor interface."""
        if not iface:
            raise SafetyViolation("no sensor interface given")
        protected = self.protected_set()
        if iface in protected:
            raise SafetyViolation(
                f"refusing to modify {iface}: it is a protected interface "
                f"(protected: {', '.join(sorted(protected))})"
            )
        if not (self.sysfs_root / iface).exists():
            raise SafetyViolation(f"refusing to modify {iface}: interface does not exist")
        if not (self.sysfs_root / iface / "phy80211").exists():
            raise SafetyViolation(f"refusing to modify {iface}: not a wireless interface")

    # -- snapshots -----------------------------------------------------------
    def _nm_state(self, iface: str) -> str | None:
        if self._nm_state_lookup is not None:
            return self._nm_state_lookup(iface)
        res = self.runner.run(["nmcli", "-t", "-f", "DEVICE,STATE", "device", "status"])
        if not res.ok:
            return None
        for line in res.stdout.splitlines():
            dev, _, state = line.partition(":")
            if dev == iface:
                return state
        return None

    def snapshot(self, iface: str) -> InterfaceSnapshot:
        exists = (self.sysfs_root / iface).exists()
        snap = InterfaceSnapshot(name=iface, exists=exists)
        if not exists:
            return snap
        snap.operstate = self._read(iface, "operstate")
        snap.mac = (self._read(iface, "address") or "").upper() or None
        snap.phy = self.phy_of(iface)
        res = self.runner.run(["iw", "dev", iface, "info"])
        if res.ok:
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.startswith("type "):
                    snap.iftype = line.split(None, 1)[1]
                elif line.startswith("ssid "):
                    snap.ssid = line.split(None, 1)[1]
                elif line.startswith("channel "):
                    snap.channel = line.split(None, 1)[1]
        snap.nm_state = self._nm_state(iface)
        return snap

    def snapshot_protected(self) -> dict[str, InterfaceSnapshot]:
        return {name: self.snapshot(name) for name in sorted(self.protected_set())}

    @staticmethod
    def verify_unchanged(before: Mapping[str, InterfaceSnapshot],
                         after: Mapping[str, InterfaceSnapshot]) -> dict[str, list[str]]:
        """Map interface -> list of differences, only for interfaces that changed."""
        changes = {}
        for name, snap in before.items():
            other = after.get(name) or InterfaceSnapshot(name=name, exists=False)
            diff = snap.compare(other)
            if diff:
                changes[name] = diff
        return changes
