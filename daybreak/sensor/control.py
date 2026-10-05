"""Guarded control of the *sensor* interface (monitor mode / channel only).

Every mutating command is preceded by :meth:`InterfaceGuard.assert_may_modify`
and followed by verification that protected interfaces (``wlo1``) did not
change. Commands only ever target the configured sensor interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..safety import CommandResult, CommandRunner, InterfaceGuard, SafetyViolation


def sensor_identity_problem(sensor_cfg: Any, found: Any, *, require_disconnected: bool) -> str | None:
    """Why the interface ``found`` (a discovered interface) must not be changed as the sensor.

    It must carry the configured MAC and driver, and with ``require_disconnected`` (prepare and
    release) it must not be in use: taking a connected interface down makes it send its own
    deauthentication, and a connected interface, an access point or a mesh node may be a link
    the operator relies on.
    """
    if found is None:
        return "interface not found"
    mac = (getattr(found, "mac", None) or "").upper()
    if sensor_cfg.expected_mac and mac != sensor_cfg.expected_mac.upper():
        return f"MAC {mac or '?'} is not the configured sensor adapter ({sensor_cfg.expected_mac.upper()})"
    driver = getattr(found, "driver", None)
    if sensor_cfg.expected_driver and driver != sensor_cfg.expected_driver:
        return f"driver {driver or '?'} is not the expected sensor driver ({sensor_cfg.expected_driver})"
    if require_disconnected:
        state = getattr(found, "nm_state", None) or ""
        if state.startswith("connect"):
            return (f"it is connected to a network (NetworkManager: {state}); disconnect it yourself first - "
                    "daybreak-wids does not take down a connected interface")
        iftype = getattr(found, "iftype", None)
        if iftype == "managed" and getattr(found, "ssid", None):
            return "it is associated with a network; disconnect it yourself first"
        if iftype not in (None, "managed", "monitor"):
            return (f"it is in {iftype} mode (an access point, ad-hoc or mesh link?); stop that yourself "
                    "first - daybreak-wids only switches between managed and monitor mode")
    return None


@dataclass
class OperationReport:
    action: str
    interface: str
    dry_run: bool
    commands: list[list[str]] = field(default_factory=list)
    results: list[CommandResult] = field(default_factory=list)
    protected_changes: dict[str, list[str]] = field(default_factory=dict)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and not self.protected_changes and all(r.ok for r in self.results)


class SensorController:
    def __init__(self, interface: str, guard: InterfaceGuard, runner: CommandRunner,
                 *, nm_running: bool | None = True, expected_mac: str | None = None):
        self.interface = interface
        self.guard = guard
        self.runner = runner
        self.nm_running = nm_running
        # The sensor's MAC (configured, or learned on first use): a command is never sent to
        # an interface name that now belongs to another adapter (USB re-enumeration).
        self.expected_mac = expected_mac.upper() if expected_mac else None

    def _check_target(self) -> tuple[str | None, str | None]:
        """Guard + adapter identity check; returns the (ifindex, MAC) the commands may run on."""
        self.guard.assert_may_modify(self.interface)
        ident = self.guard.identity(self.interface)
        if self.expected_mac and ident[1] != self.expected_mac:
            raise SafetyViolation(f"refusing to modify {self.interface}: MAC {ident[1]} is not the sensor "
                                  f"adapter ({self.expected_mac})")
        if self.expected_mac is None and ident[1]:
            self.expected_mac = ident[1]
        return ident

    # -- plans ----------------------------------------------------------------
    def plan_prepare(self, channel: int | None = None) -> list[list[str]]:
        i = self.interface
        plan = []
        if self.nm_running:
            plan.append(["nmcli", "device", "set", i, "managed", "no"])
        plan += [
            ["ip", "link", "set", i, "down"],
            ["iw", "dev", i, "set", "type", "monitor"],
            ["ip", "link", "set", i, "up"],
        ]
        if channel:
            plan.append(["iw", "dev", i, "set", "channel", str(int(channel))])
        return plan

    def plan_release(self) -> list[list[str]]:
        i = self.interface
        plan = [
            ["ip", "link", "set", i, "down"],
            ["iw", "dev", i, "set", "type", "managed"],
            ["ip", "link", "set", i, "up"],
        ]
        if self.nm_running:
            plan.append(["nmcli", "device", "set", i, "managed", "yes"])
        return plan

    # -- execution --------------------------------------------------------------
    def _execute(self, action: str, plan: list[list[str]]) -> OperationReport:
        report = OperationReport(action=action, interface=self.interface,
                                 dry_run=self.runner.dry_run, commands=plan)
        for argv in plan:
            if self.interface not in argv:
                raise SafetyViolation(f"command does not target the sensor interface: {argv}")
        try:
            ident = self._check_target()
        except SafetyViolation as exc:
            report.error = str(exc)
            return report
        before = self.guard.snapshot_protected()
        for argv in plan:
            # Re-check before every step: names, routes and NetworkManager state can change
            # while a plan runs (right after a USB re-enumeration in particular).
            try:
                if self._check_target() != ident:
                    raise SafetyViolation(f"{self.interface} changed identity during {action}; stopping")
            except SafetyViolation as exc:
                report.error = str(exc)
                break
            res = self.runner.run(argv, mutating=True, guard=self.guard)
            report.results.append(res)
            if not res.ok:
                report.error = f"{' '.join(argv)} failed: {res.stderr.strip() or res.returncode}"
                break
        after = self.guard.snapshot_protected()
        report.protected_changes = self.guard.verify_unchanged(before, after)
        return report

    def prepare(self, channel: int | None = None) -> OperationReport:
        return self._execute("prepare", self.plan_prepare(channel))

    def release(self) -> OperationReport:
        return self._execute("release", self.plan_release())

    def set_channel(self, channel: int) -> CommandResult:
        self._check_target()
        return self.runner.run(["iw", "dev", self.interface, "set", "channel", str(int(channel))],
                               mutating=True, guard=self.guard)
