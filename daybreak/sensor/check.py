"""``sensor check``: read-only readiness diagnosis for the sensor adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from ..safety import InterfaceGuard, InterfaceSnapshot, SafetyViolation
from .discovery import Discovery, WirelessInterface, capability_effective

OK, INFO, WARN, FAIL = "ok", "info", "warn", "fail"


@dataclass
class CheckResult:
    name: str
    level: str
    message: str
    hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "level": self.level, "message": self.message, "hint": self.hint}


@dataclass
class SensorReport:
    sensor: WirelessInterface | None
    checks: list[CheckResult] = field(default_factory=list)
    protected_before: dict[str, InterfaceSnapshot] = field(default_factory=dict)
    protected_changes: dict[str, list[str]] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not any(c.level == FAIL for c in self.checks)

    def add(self, name: str, level: str, message: str, hint: str | None = None) -> None:
        self.checks.append(CheckResult(name, level, message, hint))


def nm_unmanaged_hint(iface: str, mac: str | None) -> str:
    match = f"mac:{mac.lower()}" if mac else f"interface-name:{iface}"
    return (f"sensor only (runtime): sudo nmcli device set {iface} managed no ; persistent: create "
            f"/etc/NetworkManager/conf.d/99-daybreak-sensor.conf with lines '[keyfile]' and "
            f"'unmanaged-devices={match}', then reload NetworkManager. "
            "daybreak-wids never changes this for you.")


def run_sensor_checks(cfg: Config, discovery: Discovery, guard: InterfaceGuard,
                      *, proc_status: str = "/proc/self/status") -> SensorReport:
    """Diagnose the configured sensor without modifying anything."""
    before = guard.snapshot_protected()
    name = cfg.sensor.interface
    iface = discovery.interface(name)
    report = SensorReport(sensor=iface, protected_before=before)

    if iface is None and cfg.sensor.expected_mac:
        iface = discovery.find_by_mac(cfg.sensor.expected_mac)
        if iface is not None:
            report.sensor = iface
            report.add("presence", WARN,
                       f"{name} not found, but adapter {cfg.sensor.expected_mac} is present as {iface.name}",
                       f"set sensor.interface: {iface.name}")
    if iface is None:
        report.add("presence", FAIL, f"sensor interface {name} not found",
                   "is the ALFA adapter plugged in? (`lsusb | grep -i 0e8d`, `iw dev`)")
    else:
        if iface.name == name:
            report.add("presence", OK, f"{iface.name} present ({iface.phy}, {iface.bus or 'unknown bus'}"
                       + (f" {iface.usb_id}" if iface.usb_id else "") + ")")
        _check_sensor(cfg, iface, guard, report, proc_status)

    # The check itself is read-only; prove it.
    after = guard.snapshot_protected()
    report.protected_changes = guard.verify_unchanged(before, after)
    if report.protected_changes:
        report.add("protected-interfaces", FAIL,
                   "protected interface state changed during check: "
                   + "; ".join(f"{k}: {', '.join(v)}" for k, v in report.protected_changes.items()))
    else:
        names = ", ".join(sorted(before)) or "none"
        report.add("protected-interfaces", OK, f"unchanged ({names})")
    missing = guard.missing_configured()
    if missing:
        report.add("protected-config", WARN, f"configured protected interface(s) not found: {', '.join(missing)}",
                   "fix sensor.protected_interfaces: a misspelled name protects nothing "
                   "(`sensor prepare --apply` refuses until it is fixed)")
    return report


def _check_sensor(cfg: Config, iface: WirelessInterface, guard: InterfaceGuard,
                  report: SensorReport, proc_status: str) -> None:
    expected = cfg.sensor.expected_driver
    if expected:
        if iface.driver == expected:
            report.add("driver", OK, f"driver {iface.driver}")
        else:
            report.add("driver", WARN, f"driver {iface.driver or 'unknown'} (expected {expected})")
    if cfg.sensor.expected_mac:
        if iface.mac == cfg.sensor.expected_mac:
            report.add("mac", OK, f"MAC {iface.mac}")
        else:
            report.add("mac", WARN, f"MAC {iface.mac} differs from sensor.expected_mac {cfg.sensor.expected_mac}")

    try:
        guard.assert_may_modify(iface.name)
        report.add("isolation", OK, "dedicated adapter (not protected, no default route, separate PHY)")
    except SafetyViolation as exc:
        report.add("isolation", FAIL, str(exc),
                   "use a dedicated USB adapter as sensor; never the internet interface")

    if iface.monitor_supported:
        report.add("monitor", OK, "monitor mode supported")
    elif iface.monitor_supported is False:
        report.add("monitor", FAIL, "monitor mode not supported by this PHY")
    else:
        report.add("monitor", WARN, "could not determine monitor mode support (`iw phy` failed)")

    if iface.bands:
        report.add("bands", OK, "bands " + " / ".join(iface.bands) + " GHz")

    if iface.iftype == "monitor":
        ch = f", channel {iface.channel}" if iface.channel else ""
        report.add("mode", OK, f"interface is in monitor mode{ch}")
    else:
        report.add("mode", INFO, f"interface is in {iface.iftype or 'unknown'} mode",
                   "Kismet switches it to monitor mode itself; for the built-in passive backend run "
                   f"`sudo daybreak-wids sensor prepare --apply` (touches {iface.name} only)")

    if iface.nm_state is None:
        report.add("networkmanager", INFO, "NetworkManager not running or nmcli unavailable")
    elif iface.nm_state == "unmanaged":
        report.add("networkmanager", OK, "sensor is not managed by NetworkManager")
    else:
        level = WARN
        msg = f"NetworkManager manages the sensor (state: {iface.nm_state})"
        if iface.nm_state.startswith("connected") or iface.ssid:
            msg += f"; it is connected as a client{' to ' + iface.ssid if iface.ssid else ''}"
        report.add("networkmanager", level, msg, nm_unmanaged_hint(iface.name, iface.mac))

    if iface.regdomain:
        if iface.regdomain == "00":
            report.add("regdomain", WARN, "regulatory domain is 00 (world); 5/6 GHz channels may be limited",
                       "set your country: sudo iw reg set KR")
        else:
            report.add("regdomain", OK, f"regulatory domain {iface.regdomain}")

    caps = capability_effective(proc_status)
    if "CAP_NET_RAW" in caps:
        report.add("privileges", OK, "CAP_NET_RAW available (passive frame capture possible)")
    else:
        report.add("privileges", INFO, "no CAP_NET_RAW: passive frame capture needs root or "
                   "`setcap cap_net_raw+ep`; the Kismet backend works without it")
