"""Passive-only safety model.

daybreak-wids never constructs or sends 802.11 frames. There is no injection,
deauthentication, handshake capture/export, cracking or password-guessing code
in this package; ``tests/test_safety.py`` checks some literal forms of these
statically (a tripwire for code review, not a sandbox).

This module covers the remaining risk: changing the *wrong* network interface.
Only the dedicated sensor interface may ever be reconfigured (monitor mode,
channel). Interfaces listed in ``sensor.protected_interfaces`` (``wlo1`` by
default), any interface that carries the default route, and any interface that
shares a PHY with one of those are off-limits, and their state is snapshotted
before and verified after every sensor operation.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, NamedTuple, Sequence


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

def valid_ifname(name: Any) -> bool:
    """Linux interface-name rules (1-15 bytes, no '/', ':' or whitespace, not '.' or '..'),
    plus: printable, and no leading '-' (it would read as an option)."""
    if not isinstance(name, str) or name in ("", ".", "..") or name.startswith("-"):
        return False
    try:
        size = len(name.encode("utf-8"))
    except UnicodeEncodeError:
        return False
    return size <= 15 and name.isprintable() and not any(c in "/:" or c.isspace() for c in name)


class AllowedCommand(NamedTuple):
    pattern: tuple[Any, ...]   # None: a variable argument (interface / PHY name, channel); a set: a choice
    mutating: bool
    iface: int | None = None   # for interface-changing commands: index of the interface argument


# The only host commands daybreak-wids runs. Checked at runtime by CommandRunner (interface-changing
# ones also pass the interface guard there) and statically over the source by tests/test_safety.py.
COMMAND_ALLOW_LIST: tuple[AllowedCommand, ...] = (
    AllowedCommand(("iw", "phy", None, "info"), False),
    AllowedCommand(("iw", "dev", None, "info"), False),
    AllowedCommand(("iw", "reg", "get"), False),
    AllowedCommand(("iw", "dev", None, "set", "type", frozenset({"monitor", "managed"})), True, 2),
    AllowedCommand(("iw", "dev", None, "set", "channel", None), True, 2),
    AllowedCommand(("ip", "link", "set", None, frozenset({"up", "down"})), True, 3),
    AllowedCommand(("nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status"), False),
    AllowedCommand(("nmcli", "-t", "-f", "DEVICE,STATE", "device", "status"), False),
    AllowedCommand(("nmcli", "device", "set", None, "managed", frozenset({"yes", "no"})), True, 3),
)

# Tools are resolved here only, never through the caller's PATH (sudo -E, an activated venv).
TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
# Read-only snapshots run inside the monitor loop: keep a hung NetworkManager from stalling capture.
SNAPSHOT_TIMEOUT = 3.0


def match_command(argv: Sequence[str]) -> AllowedCommand | None:
    """The allow-list entry ``argv`` matches, or ``None``."""
    for entry in COMMAND_ALLOW_LIST:
        if len(argv) != len(entry.pattern):
            continue
        for got, want in zip(argv, entry.pattern):
            if want is None:
                if not valid_ifname(got):  # names and channel numbers alike; never an option
                    break
            elif isinstance(want, frozenset):
                if got not in want:
                    break
            elif got != want:
                break
        else:
            return entry
    return None


def resolve_tool(name: str) -> str | None:
    """Absolute path of ``name`` in :data:`TRUSTED_PATH`; as root only root-owned, not writable by others."""
    path = shutil.which(name, path=TRUSTED_PATH)
    if path is None:
        return None
    if os.geteuid() == 0:
        st = os.stat(path)
        if st.st_uid != 0 or st.st_mode & 0o022:
            return None
    return path


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def checked_command(argv: Sequence[str], mutating: bool = False, guard: "InterfaceGuard | None" = None) -> bool:
    """Raise unless ``argv`` is allow-listed; return whether it changes state.

    Whether it changes state comes from the allow-list, not only from the caller, and an
    interface-changing command is refused unless the interface guard approves its interface.
    """
    entry = match_command(argv)
    if entry is None:
        raise SafetyViolation(f"command is not allow-listed: {list(argv)}")
    if mutating or entry.mutating:
        if entry.iface is None:
            raise SafetyViolation(f"refusing {' '.join(argv)}: not an interface-changing command")
        if guard is None:
            raise SafetyViolation(f"refusing {' '.join(argv)}: interface-changing commands need the interface guard")
        guard.assert_may_modify(argv[entry.iface])
        return True
    return False


class CommandRunner:
    """Runs allow-listed inspection commands and guarded sensor commands (argv lists, no shell)."""

    def __init__(self, dry_run: bool = False, timeout: float = 10.0):
        self.dry_run = dry_run
        self.timeout = timeout
        self.history: deque[list[str]] = deque(maxlen=200)  # recent commands, bounded

    def run(self, argv: Sequence[str], *, mutating: bool = False,
            guard: "InterfaceGuard | None" = None, timeout: float | None = None) -> CommandResult:
        argv = list(argv)
        mutating = checked_command(argv, mutating, guard)
        self.history.append(argv)
        if mutating and self.dry_run:
            return CommandResult(argv, 0, "", "dry-run: not executed")
        exe = resolve_tool(argv[0])
        if exe is None:
            return CommandResult(argv, 127, "", f"{argv[0]}: command not found in {TRUSTED_PATH}")
        # Minimal environment: children never see API keys or the caller's PATH.
        env = {"PATH": TRUSTED_PATH, "LC_ALL": "C", "LANG": "C"}
        try:
            proc = subprocess.run([exe, *argv[1:]], capture_output=True, text=True,
                                  timeout=self.timeout if timeout is None else timeout, env=env, check=False)
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
        for name in ("exists", "operstate", "mac", "phy", "iftype", "ssid", "nm_state"):
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
        # Pinned at the start of a run: these stay protected even if the default route moves
        # or the interface is renamed (matched by MAC / PHY as well as by name).
        self.pinned_names: set[str] = set()
        self.pinned_macs: set[str] = set()
        self.pinned_phys: set[str] = set()

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

    def mac_of(self, iface: str) -> str | None:
        return (self._read(iface, "address") or "").upper() or None

    def identity(self, iface: str) -> tuple[str | None, str | None]:
        """(ifindex, MAC) of ``iface``: changes if the name now belongs to another device."""
        return self._read(iface, "ifindex"), self.mac_of(iface)

    def _entries(self) -> list[str]:
        try:
            return sorted(os.listdir(self.sysfs_root))
        except OSError:
            return []

    def protected_set(self) -> set[str]:
        """Configured + pinned protected interfaces, default-route interfaces, PHY siblings,
        and any interface that now carries a pinned MAC."""
        protected = set(self.configured) | self.pinned_names | default_route_interfaces(self.route_file)
        phys = {p for p in (self.phy_of(i) for i in protected) if p} | self.pinned_phys
        for name in self._entries():
            if (phys and self.phy_of(name) in phys) or (self.pinned_macs and self.mac_of(name) in self.pinned_macs):
                protected.add(name)
        return protected

    def pin(self) -> set[str]:
        """Freeze the current protected set (names, MACs, PHYs) for the rest of the run."""
        current = self.protected_set()
        self.pinned_names |= current
        self.pinned_macs |= {m for m in (self.mac_of(i) for i in current) if m}
        self.pinned_phys |= {p for p in (self.phy_of(i) for i in current) if p}
        return current

    def missing_configured(self) -> list[str]:
        """Configured protected interfaces that do not exist (a typo protects nothing)."""
        entries = set(self._entries())
        return [i for i in self.configured if i not in entries]

    def assert_may_modify(self, iface: str) -> None:
        """Raise :class:`SafetyViolation` unless ``iface`` is a safe sensor interface."""
        if not iface:
            raise SafetyViolation("no sensor interface given")
        if not valid_ifname(iface):
            raise SafetyViolation(f"refusing to modify {iface!r}: not a valid interface name")
        protected = self.protected_set()
        if iface in protected:
            raise SafetyViolation(
                f"refusing to modify {iface}: it is a protected interface "
                f"(protected: {', '.join(sorted(protected))})"
            )
        if iface not in self._entries():  # exact sysfs entry: no path normalisation ('wlo1/')
            raise SafetyViolation(f"refusing to modify {iface}: interface does not exist")
        if not (self.sysfs_root / iface / "phy80211").exists():
            raise SafetyViolation(f"refusing to modify {iface}: not a wireless interface")

    # -- snapshots -----------------------------------------------------------
    def _nm_states(self) -> dict[str, str]:
        res = self.runner.run(["nmcli", "-t", "-f", "DEVICE,STATE", "device", "status"], timeout=SNAPSHOT_TIMEOUT)
        if not res.ok:
            return {}
        out = {}
        for line in res.stdout.splitlines():
            dev, _, state = line.partition(":")
            out[dev] = state
        return out

    def _nm_state(self, iface: str, states: Mapping[str, str] | None = None) -> str | None:
        if self._nm_state_lookup is not None:
            return self._nm_state_lookup(iface)
        return (self._nm_states() if states is None else states).get(iface)

    def snapshot(self, iface: str, *, nm_states: Mapping[str, str] | None = None) -> InterfaceSnapshot:
        exists = (self.sysfs_root / iface).exists()
        snap = InterfaceSnapshot(name=iface, exists=exists)
        if not exists:
            return snap
        snap.operstate = self._read(iface, "operstate")
        snap.mac = (self._read(iface, "address") or "").upper() or None
        snap.phy = self.phy_of(iface)
        res = self.runner.run(["iw", "dev", iface, "info"], timeout=SNAPSHOT_TIMEOUT)
        if res.ok:
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.startswith("type "):
                    snap.iftype = line.split(None, 1)[1]
                elif line.startswith("ssid "):
                    snap.ssid = line.split(None, 1)[1]
                elif line.startswith("channel "):
                    snap.channel = line.split(None, 1)[1]
        snap.nm_state = self._nm_state(iface, nm_states)
        return snap

    def snapshot_protected(self) -> dict[str, InterfaceSnapshot]:
        states = None if self._nm_state_lookup is not None else self._nm_states()  # one nmcli call
        return {name: self.snapshot(name, nm_states=states) for name in sorted(self.protected_set())}

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
