import pytest

from daybreak.safety import CommandResult, InterfaceGuard, SafetyViolation
from daybreak.sensor.check import FAIL, OK, WARN, run_sensor_checks
from daybreak.sensor.control import SensorController
from daybreak.sensor.discovery import (
    Discovery, capability_effective, freq_to_channel, parse_iw_dev_info, parse_iw_phy_info,
    parse_iw_reg_get, parse_nmcli_device_status,
)
from daybreak.sensor.status import SensorHealthMonitor
from helpers import HOST, host_runner, host_sysfs

ALFA = "wlx00c0cab85c32"


# -- parsers ------------------------------------------------------------------------------

def test_parse_phy_info_mt7921u():
    info = parse_iw_phy_info("phy3", (HOST / "iw_phy3_info.txt").read_text())
    assert info.monitor_supported
    assert {"managed", "AP", "monitor"} <= set(info.supported_modes)
    assert info.bands == ["2.4", "5", "6"]
    assert 36 in info.channels["5"] and 1 in info.channels["2.4"]
    assert 233 in info.channels["6"]
    assert 14 in info.disabled_channels["2.4"]


def test_parse_dev_info():
    info = parse_iw_dev_info((HOST / "iw_dev_wlo1_info.txt").read_text())
    assert info["type"] == "managed" and info["channel"] == 9 and info["frequency"] == 2452
    assert info["ssid"] == "HomeNetwork" and info["width"] == "20 MHz"
    alfa = parse_iw_dev_info((HOST / "iw_dev_alfa_info.txt").read_text())
    assert alfa["type"] == "managed" and alfa["addr"] == "00:C0:CA:B8:5C:32"


def test_parse_reg_get():
    global_cc, per_phy = parse_iw_reg_get((HOST / "iw_reg_get.txt").read_text())
    assert global_cc == "KR"
    assert per_phy.get("phy0") == "KR"


def test_parse_nmcli():
    states = parse_nmcli_device_status((HOST / "nmcli_device_status.txt").read_text())
    assert states["wlo1"] == "connected"
    assert states[ALFA] == "disconnected"
    assert states["tun0"] == "connected"
    assert states["veth0000001"] == "unmanaged"


@pytest.mark.parametrize("freq,expected", [
    (2412, (1, "2.4")), (2472, (13, "2.4")), (2484, (14, "2.4")), (5180, (36, "5")),
    (5825, (165, "5")), (5955, (1, "6")), (7115, (233, "6")), (5935, (2, "6")), (900, (None, None)),
])
def test_freq_to_channel(freq, expected):
    assert freq_to_channel(freq) == expected


# -- discovery ------------------------------------------------------------------------------

def test_discovery_finds_alfa(tmp_path):
    fs, route = host_sysfs(tmp_path)
    disc = Discovery(host_runner(), sysfs_root=fs.net, route_file=route)
    ifaces = {i.name: i for i in disc.interfaces()}
    assert set(ifaces) == {"wlo1", ALFA}
    alfa = ifaces[ALFA]
    assert alfa.driver == "mt7921u" and alfa.phy == "phy3" and alfa.bus == "usb"
    assert alfa.usb_id == "0e8d:7961" and alfa.mac == "00:C0:CA:B8:5C:32"
    assert alfa.monitor_supported and alfa.bands == ["2.4", "5", "6"]
    assert alfa.regdomain == "KR" and alfa.nm_state == "disconnected" and alfa.nm_managed
    assert not alfa.default_route
    assert ifaces["wlo1"].default_route and ifaces["wlo1"].ssid == "HomeNetwork"
    assert disc.find_by_mac("00:c0:ca:b8:5c:32").name == ALFA


def test_capability_parsing(tmp_path):
    status = tmp_path / "status"
    status.write_text("Name:\tpython\nCapEff:\t0000000000003000\n")
    assert capability_effective(status) == {"CAP_NET_ADMIN", "CAP_NET_RAW"}
    status.write_text("CapEff:\t0000000000000000\n")
    assert capability_effective(status) == set()


# -- guard ------------------------------------------------------------------------------

def make_guard(tmp_path, runner=None, default_iface="wlo1"):
    fs, route = host_sysfs(tmp_path)
    if default_iface != "wlo1":
        route.write_text("Iface\tDestination\n")
    return fs, InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route,
                              runner=runner or host_runner())


def test_guard_protects_wlo1_and_phy_siblings(tmp_path):
    fs, guard = make_guard(tmp_path)
    fs.add_wireless("wlo1mon", phy="phy0", mac="02:00:00:00:00:01", driver="iwlwifi")
    assert {"wlo1", "wlo1mon"} <= guard.protected_set()
    for name in ("wlo1", "wlo1mon"):
        with pytest.raises(SafetyViolation, match="protected"):
            guard.assert_may_modify(name)
    guard.assert_may_modify(ALFA)  # the dedicated sensor is fine
    with pytest.raises(SafetyViolation, match="does not exist"):
        guard.assert_may_modify("wlan9")
    with pytest.raises(SafetyViolation, match="not a wireless"):
        guard.assert_may_modify("enp1s0")


def test_guard_protects_default_route_even_if_not_configured(tmp_path):
    fs, route = host_sysfs(tmp_path)
    guard = InterfaceGuard([], sysfs_root=fs.net, route_file=route, runner=host_runner())
    with pytest.raises(SafetyViolation):
        guard.assert_may_modify("wlo1")


def test_snapshot_and_verify(tmp_path):
    fs, guard = make_guard(tmp_path)
    before = guard.snapshot_protected()
    assert before["wlo1"].operstate == "up" and before["wlo1"].ssid == "HomeNetwork"
    assert guard.verify_unchanged(before, guard.snapshot_protected()) == {}
    fs.set_operstate("wlo1", "down")
    changes = guard.verify_unchanged(before, guard.snapshot_protected())
    assert "operstate: 'up' -> 'down'" in changes["wlo1"]


# -- controller ------------------------------------------------------------------------------

def test_prepare_only_touches_sensor(tmp_path):
    runner = host_runner()
    fs, guard = make_guard(tmp_path, runner)
    ctl = SensorController(ALFA, guard, runner)
    report = ctl.prepare(channel=36)
    assert report.ok, report.error
    assert runner.executed == [
        ["nmcli", "device", "set", ALFA, "managed", "no"],
        ["ip", "link", "set", ALFA, "down"],
        ["iw", "dev", ALFA, "set", "type", "monitor"],
        ["ip", "link", "set", ALFA, "up"],
        ["iw", "dev", ALFA, "set", "channel", "36"],
    ]
    assert all("wlo1" not in argv for argv in runner.executed)
    assert report.protected_changes == {}


def test_prepare_dry_run_executes_nothing(tmp_path):
    runner = host_runner(dry_run=True)
    fs, guard = make_guard(tmp_path, runner)
    report = SensorController(ALFA, guard, runner).prepare()
    assert report.ok and report.dry_run and runner.executed == []


def test_prepare_refuses_protected_interface(tmp_path):
    runner = host_runner()
    fs, guard = make_guard(tmp_path, runner)
    report = SensorController("wlo1", guard, runner).prepare()
    assert not report.ok and "protected" in report.error
    assert runner.executed == []
    with pytest.raises(SafetyViolation):
        SensorController("wlo1", guard, runner).set_channel(6)


def test_prepare_detects_collateral_change(tmp_path):
    fs_holder = {}

    def side_effect(argv):
        if argv[:3] == ["iw", "dev", ALFA] and "monitor" in argv:
            fs_holder["fs"].set_operstate("wlo1", "down")  # simulate a misbehaving driver
        return None

    runner = host_runner(on_mutate=side_effect)
    fs, guard = make_guard(tmp_path, runner)
    fs_holder["fs"] = fs
    report = SensorController(ALFA, guard, runner).prepare()
    assert not report.ok and "wlo1" in report.protected_changes


def test_failed_command_stops_plan(tmp_path):
    runner = host_runner(on_mutate=lambda argv: CommandResult(argv, 1, "", "Operation not permitted")
                         if argv[0] == "ip" else None)
    fs, guard = make_guard(tmp_path, runner)
    report = SensorController(ALFA, guard, runner).prepare()
    assert not report.ok and "Operation not permitted" in report.error
    assert len(runner.executed) == 2  # nmcli + first ip; stopped afterwards


# -- health ------------------------------------------------------------------------------

def test_sensor_lost_and_recovered(tmp_path):
    fs, _ = host_sysfs(tmp_path)
    mon = SensorHealthMonitor(ALFA, sysfs_root=fs.net)
    assert mon.check(100.0) is None  # online; MAC learned
    assert mon.expected_mac == "00:C0:CA:B8:5C:32"
    fs.remove(ALFA)  # USB unplug / driver reset
    lost = mon.check(105.0)
    assert lost.status == "SENSOR_LOST" and lost.interface == ALFA
    assert mon.check(110.0) is None  # no repeated LOST
    fs.add_wireless(ALFA, phy="phy4", mac="00:c0:ca:b8:5c:32", driver="mt7921u", usb_id="0e8d:7961")
    rec = mon.check(130.0)
    assert rec.status == "SENSOR_RECOVERED" and rec.details["offline_seconds"] == 25.0
    assert not rec.details["renamed"]
    assert mon.check(135.0) is None


def test_sensor_recovered_under_new_name(tmp_path):
    fs, _ = host_sysfs(tmp_path)
    mon = SensorHealthMonitor(ALFA, expected_mac="00:C0:CA:B8:5C:32", sysfs_root=fs.net)
    mon.check(1.0)
    fs.remove(ALFA)
    assert mon.check(2.0).status == "SENSOR_LOST"
    fs.add_wireless("wlan1", phy="phy5", mac="00:c0:ca:b8:5c:32", driver="mt7921u")
    rec = mon.check(3.0)
    assert rec.status == "SENSOR_RECOVERED" and rec.interface == "wlan1" and rec.details["renamed"]


def test_other_adapter_with_same_name_is_not_the_sensor(tmp_path):
    fs, _ = host_sysfs(tmp_path)
    mon = SensorHealthMonitor(ALFA, expected_mac="00:C0:CA:B8:5C:32", sysfs_root=fs.net)
    mon.check(1.0)
    fs.remove(ALFA)
    fs.add_wireless(ALFA, phy="phy6", mac="02:11:11:11:11:11", driver="rtl8812au")
    assert mon.check(2.0).status == "SENSOR_LOST"


def test_missing_at_startup_reports_lost(tmp_path):
    fs, _ = host_sysfs(tmp_path)
    mon = SensorHealthMonitor("wlx001122334455", sysfs_root=fs.net)
    t = mon.check(1.0)
    assert t.status == "SENSOR_LOST" and t.details["at_startup"]


# -- sensor check ------------------------------------------------------------------------------

def test_sensor_check_reference_host(tmp_path, config):
    fs, route = host_sysfs(tmp_path)
    runner = host_runner()
    disc = Discovery(runner, sysfs_root=fs.net, route_file=route)
    guard = InterfaceGuard(config.sensor.protected_interfaces, sysfs_root=fs.net,
                           route_file=route, runner=runner)
    proc = tmp_path / "status"
    proc.write_text("CapEff:\t0000000000000000\n")
    report = run_sensor_checks(config, disc, guard, proc_status=str(proc))
    levels = {c.name: c.level for c in report.checks}
    assert report.ok
    assert levels["presence"] == OK and levels["driver"] == OK and levels["monitor"] == OK
    assert levels["isolation"] == OK and levels["networkmanager"] == WARN
    assert levels["protected-interfaces"] == OK
    nm = next(c for c in report.checks if c.name == "networkmanager")
    assert "managed no" in nm.hint and "never changes this" in nm.hint
    assert not [argv for argv in runner.history if "set" in argv]  # read-only


def test_sensor_check_missing_adapter(tmp_path, config):
    fs, route = host_sysfs(tmp_path)
    fs.remove(ALFA)
    runner = host_runner()
    disc = Discovery(runner, sysfs_root=fs.net, route_file=route)
    guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=runner)
    report = run_sensor_checks(config, disc, guard, proc_status=str(tmp_path / "none"))
    assert not report.ok
    assert next(c for c in report.checks if c.name == "presence").level == FAIL
