"""Regression tests for the pre-release security review (see docs/VALIDATION.md).

The interface guard, command runner, backend selection, sensor recovery and
runtime file handling must keep the protected interface (wlo1) and the
operator's data safe even under misconfiguration or USB re-enumeration.
"""

import os
import stat
import subprocess
from types import SimpleNamespace as NS

import pytest

import daybreak.cli as cli
import daybreak.fileperm as fileperm
import daybreak.safety as safety
from conftest import make_config
from daybreak.config import ConfigError, config_from_dict
from daybreak.safety import InterfaceGuard, InterfaceSnapshot, SafetyViolation
from daybreak.sensor.control import SensorController
from daybreak.sensor.select import choose_backend, passive_backend
from daybreak.storage import Database
from helpers import host_runner, host_sysfs, write_route_file
from kismet_fake import FakeKismet

ALFA = "wlx00c0cab85c32"
ALFA_MAC = "00:C0:CA:B8:5C:32"


# -- command runner ---------------------------------------------------------------------------

def test_runner_refuses_commands_outside_the_allow_list(monkeypatch):
    calls = []
    monkeypatch.setattr(safety.subprocess, "run", lambda argv, **kw: calls.append(argv))
    runner = safety.CommandRunner()
    for argv in (["rm", "-rf", "/"],
                 ["iw", "dev", "-h", "info"],                                   # option injection
                 ["iw", "dev", ALFA, "set", "txpower", "fixed", "3000"],         # not a sensor operation
                 ["iw", "dev", ALFA, "interface", "add", "mon0", "type", "monitor"],
                 ["iw", "dev", ALFA, "set", "type", "monitor", "active"],        # active monitor ACKs frames
                 ["ip", "link", "set", "wlo1/", "down"]):                        # path-like name
        with pytest.raises(SafetyViolation, match="not allow-listed"):
            runner.run(argv)
    assert calls == []


def test_runner_uses_trusted_paths_and_a_minimal_environment(monkeypatch):
    calls = []

    def fake_run(argv, **kw):
        calls.append((argv, kw["env"]))
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    monkeypatch.setattr(safety.subprocess, "run", fake_run)
    monkeypatch.setattr(safety, "resolve_tool", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setenv("KISMET_API_KEY", "secret-from-the-environment")
    monkeypatch.setenv("PATH", "/home/someone/.local/bin:/usr/bin")
    assert safety.CommandRunner().run(["iw", "dev", ALFA, "info"]).stdout == "ok"
    argv, env = calls[-1]
    assert argv == ["/usr/sbin/iw", "dev", ALFA, "info"]
    assert env == {"PATH": safety.TRUSTED_PATH, "LC_ALL": "C", "LANG": "C"}


def test_dry_run_is_derived_from_the_command_not_the_caller(monkeypatch, tmp_path):
    monkeypatch.setattr(safety.subprocess, "run", lambda *a, **kw: pytest.fail("executed in dry-run"))
    fs, route = host_sysfs(tmp_path)
    guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=host_runner())
    runner = safety.CommandRunner(dry_run=True)
    res = runner.run(["iw", "dev", ALFA, "set", "channel", "6"], guard=guard)  # mutating=False
    assert res.stderr == "dry-run: not executed"


def test_interface_changing_commands_need_the_guard_even_in_the_runner(monkeypatch, tmp_path):
    monkeypatch.setattr(safety.subprocess, "run", lambda *a, **kw: pytest.fail("executed"))
    fs, route = host_sysfs(tmp_path)
    guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=host_runner())
    runner = safety.CommandRunner(dry_run=True)
    with pytest.raises(SafetyViolation, match="need the interface guard"):
        runner.run(["ip", "link", "set", ALFA, "down"])
    for argv in (["ip", "link", "set", "wlo1", "down"], ["nmcli", "device", "set", "wlo1", "managed", "no"],
                 ["iw", "dev", "wlo1", "set", "type", "monitor"]):
        with pytest.raises(SafetyViolation, match="protected"):
            runner.run(argv, guard=guard)


def test_runner_history_is_bounded(monkeypatch):
    monkeypatch.setattr(safety, "resolve_tool", lambda name: None)
    runner = safety.CommandRunner()
    for _ in range(1000):
        runner.run(["iw", "reg", "get"])
    assert len(runner.history) == runner.history.maxlen == 200


# -- interface guard --------------------------------------------------------------------------

def test_guard_rejects_name_aliases_of_protected_interfaces(tmp_path):
    fs, route = host_sysfs(tmp_path)
    guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=host_runner())
    for alias in ("wlo1/", "./wlo1", "wlo1/.", "-h", f"{ALFA} ", "", "a" * 16):
        with pytest.raises(SafetyViolation):
            guard.assert_may_modify(alias)
    guard.assert_may_modify(ALFA)


def test_pinned_protection_survives_route_changes_and_renames(tmp_path):
    fs, route = host_sysfs(tmp_path)
    fs.add_wireless("wlan9", phy="phy9", mac="02:00:00:00:00:99", driver="rtl8812au")
    write_route_file(route, "wlan9")                  # wlan9 carries the default route at start
    guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=host_runner())
    assert {"wlo1", "wlan9"} <= guard.pin()
    write_route_file(route, "wlo1")                   # ...then the route moves away
    with pytest.raises(SafetyViolation, match="protected"):
        guard.assert_may_modify("wlan9")
    fs.remove("wlan9")                                # re-enumerated under a new name, same MAC
    fs.add_wireless("wlan10", phy="phy10", mac="02:00:00:00:00:99", driver="rtl8812au")
    with pytest.raises(SafetyViolation, match="protected"):
        guard.assert_may_modify("wlan10")
    guard.assert_may_modify(ALFA)


def test_missing_protected_interface_is_reported(tmp_path):
    fs, route = host_sysfs(tmp_path)
    guard = InterfaceGuard(["wlo2", "wlo1"], sysfs_root=fs.net, route_file=route, runner=host_runner())
    assert guard.missing_configured() == ["wlo2"]


# -- sensor controller ------------------------------------------------------------------------

def test_controller_refuses_another_adapter_with_the_sensor_name(tmp_path):
    fs, route = host_sysfs(tmp_path)
    runner = host_runner()
    guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=runner)
    report = SensorController(ALFA, guard, runner, expected_mac="00:C0:CA:00:00:99").prepare(36)
    assert "not the sensor adapter" in report.error and runner.executed == []


def test_controller_stops_when_the_interface_changes_identity_mid_plan(tmp_path):
    fs, route = host_sysfs(tmp_path)

    def swap(argv):  # after 'ip link set ... down' the name suddenly belongs to another adapter
        if argv[:3] == ["ip", "link", "set"] and argv[-1] == "down":
            fs.remove(ALFA)
            fs.add_wireless(ALFA, phy="phy7", mac="02:00:00:00:00:77", driver="rtl8812au")

    runner = host_runner(on_mutate=swap)
    guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=runner)
    report = SensorController(ALFA, guard, runner).prepare(36)  # learns the ALFA's MAC first
    assert not report.ok and "not the sensor adapter" in report.error
    assert [a[:3] for a in runner.executed] == [["nmcli", "device", "set"], ["ip", "link", "set"]]


# -- passive backend --------------------------------------------------------------------------

def test_channel_hopping_follows_a_rename_but_never_another_adapter(tmp_path):
    cfg = make_config(tmp_path, sensor={"interface": ALFA, "expected_mac": ALFA_MAC, "channels": [36, 6]})
    fs, route = host_sysfs(tmp_path)
    runner = host_runner()
    guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=runner)
    backend = passive_backend(cfg, guard=guard, runner=runner)
    backend.set_channel(6)
    assert runner.executed[-1] == ["iw", "dev", ALFA, "set", "channel", "6"]
    fs.remove(ALFA)
    fs.add_wireless("wlan5", phy="phy5", mac=ALFA_MAC, driver="mt7921u")            # USB reset: new name
    fs.add_wireless(ALFA, phy="phy6", mac="02:00:00:00:00:66", driver="rtl8812au")  # old name, other adapter
    with pytest.raises(SafetyViolation, match="not the sensor adapter"):
        backend.set_channel(36)                       # still pointing at the old name
    backend.set_interface("wlan5")                    # what SENSOR_RECOVERED does
    backend.set_channel(36)
    assert runner.executed[-1] == ["iw", "dev", "wlan5", "set", "channel", "36"]


def test_dry_run_does_not_pretend_to_hop(tmp_path):
    cfg = make_config(tmp_path, sensor={"interface": ALFA, "channels": [36, 6]})
    fs, route = host_sysfs(tmp_path)
    runner = host_runner(dry_run=True)
    guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=runner)
    assert passive_backend(cfg, guard=guard, runner=runner).set_channel is None


# -- backend selection --------------------------------------------------------------------------

def test_kismet_auth_failure_never_falls_back_to_the_passive_backend(tmp_path, monkeypatch):
    monkeypatch.delenv("DAYBREAK_TEST_KISMET_KEY", raising=False)
    with FakeKismet() as fk:
        cfg = make_config(tmp_path, backend={"type": "auto", "kismet": {
            "url": fk.url, "api_key_env": "DAYBREAK_TEST_KISMET_KEY", "timeout": 2}})
        fs, route = host_sysfs(tmp_path)
        runner = host_runner()
        guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=runner)
        with pytest.raises(ValueError, match="will not fall back"):
            choose_backend(cfg, guard=guard, runner=runner, log=lambda m: None)
    assert runner.executed == []


# -- sensor recovery (auto_prepare) -------------------------------------------------------------

def test_recovery_only_targets_the_configured_sensor(tmp_path):
    cfg = make_config(tmp_path, sensor={"interface": ALFA, "expected_mac": ALFA_MAC})
    rec = cli.SensorRecovery(cfg, guard=None, runner=None)
    assert rec.is_sensor("wlan5", NS(mac=ALFA_MAC.lower(), driver="mt7921u"))       # renamed sensor
    assert not rec.is_sensor("wlp2s0", NS(mac=ALFA_MAC.lower(), driver="iwlwifi"))  # MAC copied from wrong NIC
    assert not rec.is_sensor("wlan5", NS(mac="02:00:00:00:00:01", driver="mt7921u"))
    assert not rec.is_sensor(ALFA, None)
    name_only = cli.SensorRecovery(make_config(tmp_path, sensor={"interface": ALFA}), guard=None, runner=None)
    assert name_only.is_sensor(ALFA, NS(mac=ALFA_MAC.lower(), driver="mt7921u"))
    assert not name_only.is_sensor("wlan5", NS(mac=ALFA_MAC.lower(), driver="mt7921u"))


def test_recovery_stays_off_after_a_protected_change(tmp_path):
    rec = cli.SensorRecovery(make_config(tmp_path), guard=None, runner=None)
    rec.disabled = "protected interface changed during recovery"
    assert rec(ALFA) is False


# -- live monitor: continuous protected-interface verification ------------------------------------

def test_protected_interface_change_is_alerted_and_stops_auto_prepare(tmp_path):
    from test_monitor import T0, FakeBackend, FakeClock, runtime

    from daybreak.monitor import MonitorRunner

    rt = runtime(tmp_path)

    class Guard:
        state = "connected"

        def snapshot_protected(self):
            return {"wlo1": InterfaceSnapshot("wlo1", True, operstate="up", nm_state=self.state)}

        verify_unchanged = staticmethod(InterfaceGuard.verify_unchanged)

    guard = Guard()
    clock = FakeClock(start=T0, step=1.0)
    clock.at(15, lambda: setattr(guard, "state", "disconnected"))
    runner = MonitorRunner(rt, FakeBackend([]), duration=40, clock=clock, sleep=lambda s: None,
                           guard=guard, recover=lambda iface: True)
    runner.run()
    alerts = rt.db.list_alerts(alert_type="PROTECTED_INTERFACE_CHANGED")
    assert len(alerts) == 1 and alerts[0]["severity"] == "MEDIUM"
    assert "nm_state: 'connected' -> 'disconnected'" in alerts[0]["reason"]["components"][0]["detail"]
    assert runner.recover is None   # no further sensor re-preparation in this run
    assert "PROTECTED_CHANGED" in [r["status"] for r in rt.db.latest_sensor_status(limit=10)]
    rt.close()


# -- runtime files ------------------------------------------------------------------------------

def test_runtime_files_are_owner_only(tmp_path):
    from daybreak.alerts.jsonl import rotating_logger

    db = Database(tmp_path / "var" / "d.db")
    db.close()
    assert stat.S_IMODE((tmp_path / "var" / "d.db").stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "var").stat().st_mode) == 0o700
    log = rotating_logger("daybreak.test.private", tmp_path / "logs" / "a.jsonl", max_bytes=200, backup_count=2)
    for i in range(30):
        log.info("x" * 50)  # forces rollovers
    for h in log.handlers:
        h.close()
    files = list((tmp_path / "logs").iterdir())
    assert len(files) == 3 and all(stat.S_IMODE(f.stat().st_mode) == 0o600 for f in files)


def test_files_are_handed_back_to_the_sudo_user_without_following_symlinks(tmp_path, monkeypatch):
    chowned = []
    monkeypatch.setattr(fileperm.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "4242")
    monkeypatch.setenv("SUDO_GID", "4343")
    monkeypatch.setattr(fileperm.os, "fchown",
                        lambda fd, u, g: chowned.append((os.readlink(f"/proc/self/fd/{fd}"), u, g)))
    (tmp_path / "f").write_text("x")
    (tmp_path / "link").symlink_to(tmp_path / "f")
    fileperm.secure_path(tmp_path / "f")
    fileperm.secure_path(tmp_path / "link")   # O_NOFOLLOW: the link is not followed
    assert chowned == [(str(tmp_path / "f"), 4242, 4343)]
    monkeypatch.setenv("SUDO_UID", "0")
    assert fileperm.invoking_user() is None


def test_status_file_write_does_not_follow_a_planted_symlink(tmp_path):
    from test_monitor import FakeBackend, FakeClock, runtime

    from daybreak.monitor import MonitorRunner, status_path

    rt = runtime(tmp_path)
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    path = status_path(rt)
    path.parent.mkdir(parents=True, exist_ok=True)
    (path.parent / "monitor.status.tmp").symlink_to(victim)  # the old fixed temp name
    MonitorRunner(rt, FakeBackend([]), duration=2, clock=FakeClock(), sleep=lambda s: None).run()
    assert victim.read_text() == "keep me" and path.is_file() and not path.is_symlink()
    rt.close()


# -- configuration -------------------------------------------------------------------------------

@pytest.mark.parametrize("section", [
    {"sensor": {"interface": "wlx/../wlo1"}},
    {"sensor": {"interface": "-h"}},
    {"sensor": {"protected_interfaces": ["wlo1 "]}},
    {"backend": {"passive": {"interface": "a" * 16}}},
    {"sensor": {"channels": [0]}},
    {"sensor": {"channels": [234]}},
    {"sensor": {"dwell_time": 0}},
    {"sensor": {"health_check_interval": -1}},
])
def test_sensor_settings_are_validated(tmp_path, section):
    with pytest.raises(ConfigError):
        config_from_dict(section, base_dir=tmp_path)


def test_notifications_are_sent_as_plain_text():
    from daybreak.alerts.desktop import DesktopNotifier
    from daybreak.models import Alert, ScoreComponent

    sent = []
    n = DesktopNotifier("INFO", run=lambda argv, **kw: sent.append(argv), available=True)
    n.notify(Alert("KISMET_APSPOOF", 1.0, 80, [ScoreComponent(80, "x", "y")],
                   summary='<a href="http://evil.example">click</a> <img src=x>'))
    body = sent[0][-1]
    assert "<a " not in body and "&lt;a href=" in body and "<img" not in body


def test_umask_is_owner_only_after_cli_start(tmp_path):
    from click.testing import CliRunner

    old = os.umask(0o022)
    try:
        CliRunner().invoke(cli.main, ["sensor", "--help"])  # runs the main callback
        current = os.umask(0o022)
        assert current == fileperm.PRIVATE_UMASK
    finally:
        os.umask(old)


# -- secrets and privacy ---------------------------------------------------------------------------

def test_nested_metadata_cannot_smuggle_key_material():
    from daybreak.models import sanitize_metadata

    md = sanitize_metadata({"eapol_msg": 1, "note": {"key-mic": "a" * 32, "anonce_hex": "b" * 64},
                            "status": ["c" * 64], "phy": {"ht": True, "he": "yes", "nonce": "d"},
                            "Nonce": "e", "kismet_hash": {"pmkid_list": ["f" * 32]}})
    assert md == {"eapol_msg": 1, "phy": {"ht": True}}


@pytest.mark.parametrize("url", [
    "admin:pw@127.0.0.1:2501", "http:/admin:pw@127.0.0.1:2501", "http:admin:pw@kismet",
    "http://127.0.0.1:2501/?KISMET=apikey", "http://kismet/#frag", "ftp://kismet", "http://", "http://kismet:99999",
])
def test_kismet_url_is_validated_strictly_and_never_echoed(tmp_path, url):
    with pytest.raises(ConfigError) as exc:
        config_from_dict({"backend": {"kismet": {"url": url}}}, base_dir=tmp_path)
    msg = str(exc.value)
    assert "pw" not in msg and "apikey" not in msg and (url == "http://" or url not in msg)


def test_kismet_alerts_are_attributed_by_exact_ssid_or_mac(tmp_path):
    from daybreak.models import Event, EventType
    from daybreak.registry import NetworkRegistry

    reg = NetworkRegistry(make_config(tmp_path).protected_networks)  # 'home' = ExampleSSID

    def kev(text, src=None):
        return Event(1.0, EventType.KISMET_ALERT, source=src, metadata={"kismet_header": "APSPOOF",
                                                                         "kismet_text": text})

    assert reg.network_of(kev("Unauthorized device advertising for SSID 'ExampleSSID'")).name == "home"
    assert reg.network_of(kev('network SSID "ExampleSSID" changed advertised encryption')).name == "home"
    assert reg.network_of(kev("SSID 'ExampleSSID-guest' changed")) is None      # a neighbour, not 'home'
    assert reg.network_of(kev("ExampleSSID mentioned without quotes")) is None
    assert reg.network_of(kev("no SSID in the text", src="AA:BB:CC:DD:EE:FF")).name == "home"
    assert not reg.in_scope(kev("SSID 'myExampleSSID' changed"))


def test_human_alert_output_neutralises_control_characters():
    from daybreak.alerts.formatting import human_lines
    from daybreak.models import Alert, ScoreComponent

    alert = Alert("KISMET_APSPOOF", 1.0, 30, [ScoreComponent(30, "spoof", "evil\x1b]0;pwned\x07")],
                  summary="first\n2026-10-05 15:00:00 CRITICAL FORGED‮")
    lines = human_lines(alert)
    assert not any(c in line for line in lines for c in "\x1b\x07\n‮")
    assert any("\\x1b]0;pwned\\x07" in line for line in lines)
    assert any("first\\x0a2026-10-05 15:00:00 CRITICAL FORGED\\u202e" in line for line in lines)


def test_kismet_alert_text_is_capped_and_fields_are_scalars():
    from daybreak.sensor.kismet import KISMET_TEXT_MAX, alert_to_event
    from kismet_fake import NOW, alert

    rec = alert("APSPOOF", NOW, text="x" * 5000)
    rec["kismet.alert.severity"] = {"nested": 1}
    ev = alert_to_event(rec, sensor="kismet")
    assert len(ev.metadata["kismet_text"]) == KISMET_TEXT_MAX and ev.metadata.get("kismet_severity") is None


def test_kismet_check_warns_about_credentials_over_plain_http(config):
    from daybreak.sensor.kismet import KismetClient, check_kismet

    client = KismetClient("http://kismet.lan:2501", api_key="k")
    canned = {"/system/status.json": {"kismet.system.version": "test", "kismet.system.timestamp.sec": 1}}
    client.request = lambda path, fields=None: canned.get(path, [])
    assert ("warn", "transport") in [(level, name) for level, name, _ in check_kismet(client, config)]


def test_logs_are_never_opened_through_a_symlink(tmp_path):
    from daybreak.alerts.jsonl import rotating_logger

    victim = tmp_path / "victim"
    victim.write_text("keep")
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "a.jsonl").symlink_to(victim)
    with pytest.raises(OSError):
        rotating_logger("daybreak.test.symlink", tmp_path / "logs" / "a.jsonl", max_bytes=100, backup_count=1)
    assert victim.read_text() == "keep"


def test_registry_and_database_refuse_planted_symlinks(tmp_path):
    import sqlite3

    from daybreak.config import save_registry_file

    victim = tmp_path / "victim"
    victim.write_text("keep")
    (tmp_path / "networks.yaml.tmp").symlink_to(victim)          # the old fixed temporary name
    save_registry_file(tmp_path / "networks.yaml", [])
    assert victim.read_text() == "keep" and (tmp_path / "networks.yaml").is_file()
    assert stat.S_IMODE((tmp_path / "networks.yaml").stat().st_mode) == 0o600
    (tmp_path / "db.sqlite").symlink_to(victim)
    with pytest.raises(sqlite3.OperationalError, match="symlinked"):
        Database(tmp_path / "db.sqlite")
    assert victim.read_text() == "keep"


def test_secure_delete_is_enabled(tmp_path):
    db = Database(tmp_path / "s.db")
    assert db.conn.execute("PRAGMA secure_delete").fetchone()[0] == 1
    db.close()


def test_retention_removes_old_rotated_log_files(tmp_path):
    from test_monitor import T0, FakeBackend, FakeClock, runtime

    from daybreak.monitor import MonitorRunner

    rt = runtime(tmp_path, storage={"database": "var/test.db", "retention_days": 1})
    log_dir = rt.config.log_dir
    old, fresh, other = log_dir / "alerts.jsonl.3", log_dir / "daybreak.log.1", log_dir / "alerts.jsonl.bak"
    for path, mtime in ((old, T0 - 3 * 86400), (fresh, T0), (other, T0 - 3 * 86400)):
        path.write_text("x\n")
        os.utime(path, (mtime, mtime))
    MonitorRunner(rt, FakeBackend([]), duration=2, clock=FakeClock(start=T0), sleep=lambda s: None).run()
    assert not old.exists() and fresh.exists() and other.exists()
    rt.close()


# -- bounded state and storage under floods ----------------------------------------------------------

def test_beacon_flood_with_random_bssids_keeps_state_and_storage_bounded(tmp_path):
    from conftest import HOME_BSSID
    from daybreak.models import Event, EventType
    from daybreak.runtime import build_runtime

    rt = build_runtime(make_config(tmp_path))
    p = rt.pipeline
    t0 = 1_790_000_000.0
    for i in range(10_000):  # 100 beacons/s for 100 s, each from a new random BSSID
        p.process(Event(t0 + i * 0.01, EventType.BEACON, bssid=f"02:00:00:{i >> 16 & 255:02X}:{i >> 8 & 255:02X}:"
                        f"{i & 255:02X}", ssid="ExampleSSID", channel=36))
        if i % 100 == 0:  # the registered AP keeps beaconing
            p.process(Event(t0 + i * 0.01 + 0.005, EventType.BEACON, bssid=HOME_BSSID, ssid="ExampleSSID",
                            channel=36))
    p.flush()
    assert len(p.ctx.aps.aps) <= p.ctx.aps.max_aps and HOME_BSSID in p.ctx.aps.aps
    spoof = next(d for d in p.detectors if d.name == "spoof")
    assert len(spoof._reported) <= spoof.MAX_REPORTED
    rows = rt.db.count_aps(ssid="ExampleSSID", exclude_bssids=[HOME_BSSID])
    assert rows <= 256 + 100 * 256 / 3600 + 1 and p.stats["aps_not_stored"] == 10_000 - rows
    assert rt.db.list_alerts(alert_type="UNKNOWN_BSSID_FOR_PROTECTED_SSID")  # the flood is still reported
    rt.close()


def test_deauth_flood_is_detected_while_storage_is_sampled(tmp_path):
    from conftest import HOME_BSSID
    from daybreak.models import Event
    from daybreak.runtime import build_runtime

    rt = build_runtime(make_config(tmp_path))
    t0 = 1_790_000_000.0
    for i in range(5000):  # 1000 frames/s for 5 s
        rt.pipeline.process(Event.from_dict({"ts": t0 + i * 0.001, "type": "deauth", "bssid": HOME_BSSID,
                                             "src": HOME_BSSID, "dst": "FF:FF:FF:FF:FF:FF", "reason": 7,
                                             "seq": i % 4096}))
    rt.pipeline.flush()
    stored = rt.db.event_counts(since=0)["deauth"]
    assert 500 <= stored <= 500 + 50 * 5 + 1
    assert rt.pipeline.stats["events_not_stored"] == 5000 - stored
    assert rt.db.list_alerts(alert_type="POSSIBLE_DEAUTH_ATTACK")  # detection saw every frame
    rt.close()


def test_station_tracker_is_bounded():
    from daybreak.detectors.base import StationTracker
    from daybreak.models import Event, EventType

    tracker = StationTracker()
    for i in range(3000):
        tracker.observe(Event(1.0 + i, EventType.ASSOC, bssid="AA:BB:CC:DD:EE:FF",
                              station=f"10:00:00:00:{i >> 8:02X}:{i & 255:02X}"))
    assert len(tracker.seen["AA:BB:CC:DD:EE:FF"]) <= tracker.MAX_PER_BSSID
    assert "10:00:00:00:0B:B7" in tracker.seen["AA:BB:CC:DD:EE:FF"]  # the most recent station is kept


# -- transmit-path review: sensor identity, Kismet paths, frame tap, desktop -------------------------------

def test_prepare_refuses_a_connected_or_unexpected_sensor(tmp_path):
    from daybreak.sensor.control import sensor_identity_problem

    cfg = make_config(tmp_path, sensor={"interface": ALFA, "expected_mac": ALFA_MAC}).sensor
    idle = NS(mac=ALFA_MAC.lower(), driver="mt7921u", nm_state="disconnected", iftype="managed", ssid=None)
    assert sensor_identity_problem(cfg, idle, require_disconnected=True) is None
    connected = NS(**{**idle.__dict__, "nm_state": "connected"})
    assert "connected" in sensor_identity_problem(cfg, connected, require_disconnected=True)
    assert sensor_identity_problem(cfg, connected, require_disconnected=False) is None  # release is fine
    associated = NS(**{**idle.__dict__, "ssid": "SomeNetwork"})
    assert "associated" in sensor_identity_problem(cfg, associated, require_disconnected=True)
    internal = NS(mac="02:00:00:00:00:01", driver="iwlwifi", nm_state="disconnected", iftype="managed", ssid=None)
    assert "MAC" in sensor_identity_problem(cfg, internal, require_disconnected=False)
    no_mac = make_config(tmp_path, sensor={"interface": "wlo2"}).sensor   # expected_driver stays mt7921u
    assert "driver" in sensor_identity_problem(no_mac, internal, require_disconnected=False)


def test_cli_prepare_refuses_a_connected_sensor(tmp_path, monkeypatch):
    import yaml
    from click.testing import CliRunner

    import daybreak.sensor.discovery as discovery

    fs, route = host_sysfs(tmp_path)
    runners = []

    def runner_factory(dry_run=False, timeout=10.0):
        r = host_runner(dry_run=dry_run)
        r.responses[("nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status")] = (
            "wlo1:wifi:connected\nwlx00c0cab85c32:wifi:connected\n")
        runners.append(r)
        return r

    monkeypatch.setattr(cli, "CommandRunner", runner_factory)
    monkeypatch.setattr(cli, "InterfaceGuard", lambda *a, **kw: InterfaceGuard(*a, sysfs_root=fs.net,
                                                                               route_file=route, **kw))
    original = discovery.Discovery

    class FakeDiscovery(original):
        def __init__(self, runner=None, **kw):
            super().__init__(runner, sysfs_root=fs.net, route_file=route)

    monkeypatch.setattr(discovery, "Discovery", FakeDiscovery)
    monkeypatch.setattr(discovery, "capability_effective", lambda *a, **kw: {"CAP_NET_ADMIN", "CAP_NET_RAW"})
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump({"protected_networks": []}))
    r = CliRunner().invoke(cli.main, ["-c", str(path), "sensor", "prepare", "--apply", "--channel", "36"])
    assert r.exit_code == 1 and "connected to a network" in r.output
    assert all(not rr.executed for rr in runners)


@pytest.mark.parametrize("path", [
    "/system/status.json/../../datasource/by-uuid/x/set_channel.cmd",
    "/alerts/wrapped/last-time/1.000000/../../../datasource/add_source.cmd",
    "/system/status.json?KISMET=x", "/devices/last-time/1/devices.json", "/logging/active.json#frag",
    "/datasource/all_sources.json%2f..",
])
def test_kismet_paths_must_match_an_endpoint_exactly(path):
    from daybreak.sensor.kismet import KismetClient, KismetError

    with pytest.raises(KismetError, match="not allow-listed"):
        KismetClient("http://127.0.0.1:9", timeout=0.1).request(path)


def test_frame_tap_refuses_malformed_or_protected_interface_names(tmp_path):
    from daybreak.sensor.backend import BackendUnavailable

    fs, route = host_sysfs(tmp_path)
    runner = host_runner()
    guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=runner)
    with FakeKismet() as fk:
        import kismet_fake

        cfg = make_config(tmp_path, backend={"type": "kismet", "kismet": {"url": fk.url, "timeout": 2}})
        os.environ["DAYBREAK_TEST_TAP_KEY"] = kismet_fake.API_KEY
        try:
            cfg.backend.kismet.api_key_env = "DAYBREAK_TEST_TAP_KEY"
            backend = choose_backend(cfg, guard=guard, runner=runner, log=lambda m: None)
        finally:
            del os.environ["DAYBREAK_TEST_TAP_KEY"]
    for name in ("wlo1", "../wlo1", "-x"):
        with pytest.raises(BackendUnavailable, match="refusing a frame tap"):
            backend.frame_tap_factory(name)


def test_desktop_notifications_are_disabled_as_root(monkeypatch):
    from daybreak.alerts import desktop

    monkeypatch.setattr(desktop.os, "geteuid", lambda: 0)
    available, why = desktop.desktop_available()
    assert not available and "root" in why


# -- untrusted input: capture files, JSONL, timestamps, text ---------------------------------------------------

def _pcapng_block(btype, body, total=None):
    import struct

    body = body + b"\x00" * (-len(body) % 4)
    length = 12 + len(body) if total is None else total
    return struct.pack("<II", btype, length) + body + struct.pack("<I", length)


def _pcapng(*blocks):
    import struct

    shb = _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    return shb + b"".join(blocks)


def _idb(extra=b""):
    import struct

    return _pcapng_block(1, struct.pack("<HHI", 127, 0, 0) + extra)


def _epb(frame, ts_us):
    import struct

    return _pcapng_block(6, struct.pack("<IIIII", 0, ts_us >> 32, ts_us & 0xFFFFFFFF, len(frame), len(frame)) + frame)


def _read_capture(path):
    from daybreak.sensor.pcapfile import PcapFileBackend

    backend = PcapFileBackend(path)
    backend.open()
    events = []
    try:
        while not backend.finished:
            events += backend.poll(0)
    finally:
        backend.close()
    return backend, events


def test_malformed_capture_files_fail_cleanly(tmp_path):
    import struct

    import frames_hex as F
    from daybreak.sensor.backend import BackendUnavailable

    frame = F.RT_5180 + F.DEAUTH_UNICAST
    shb = _pcapng()
    cases = {
        "idb_too_short": shb + struct.pack("<III", 1, 12, 12),
        "epb_too_short": _pcapng(_idb(), _epb(frame, 1_790_000_000_000_000)) + struct.pack("<III", 6, 12, 12),
        "shb_length_zero": shb + struct.pack("<II", 0x0A0D0D0A, 0) + b"\x4d\x3c\x2b\x1a",
        "block_too_long": shb + struct.pack("<II", 6, 0x7FFFFFF0),
        "pcap_huge_record": (b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 127)
                             + struct.pack("<IIII", 1_790_000_000, 0, 0x7FFFFFFF, 0x7FFFFFFF)),
    }
    for name, data in cases.items():
        (tmp_path / name).write_bytes(data)
        with pytest.raises(BackendUnavailable):
            _read_capture(tmp_path / name)
    # an if_tsresol option without its value byte is ignored, not a crash
    (tmp_path / "tsresol").write_bytes(_pcapng(_idb(struct.pack("<HH", 9, 1))))
    _read_capture(tmp_path / "tsresol")


def test_implausible_capture_timestamps_are_skipped(tmp_path):
    import frames_hex as F

    frame = F.RT_5180 + F.DEAUTH_UNICAST
    (tmp_path / "ts.pcapng").write_bytes(_pcapng(_idb(), _epb(frame, 2**64 - 1), _epb(frame, 1_790_000_000_000_000)))
    backend, events = _read_capture(tmp_path / "ts.pcapng")
    assert len(events) == 1 and backend.stats["bad_timestamp"] == 1


def test_bad_jsonl_lines_are_counted_not_fatal():
    from daybreak.sensor.replay import ReplayBackend

    good = '{"timestamp": 1790000001, "event_type": "deauth"}'
    bad = ['{"timestamp": 1790000000, "event_type": "deauth", "rssi": Infinity}',
           '{"timestamp": 1' + "0" * 400 + ', "event_type": "deauth"}',
           '{"timestamp": 1' + "0" * 5000 + ', "event_type": "deauth"}',
           '{"timestamp": 1e12, "event_type": "deauth"}']
    backend = ReplayBackend(bad + [good])
    backend.open()
    events = backend.poll(0)
    assert len(events) == 1 and backend.stats["malformed"] == len(bad)
    # absurd nesting: either parsed (extra fields are ignored) or counted as malformed, never fatal
    nested = '{"timestamp": 1790000000, "event_type": "deauth", "x": ' + "[" * 100_000 + "]" * 100_000 + "}"
    backend = ReplayBackend([nested, good])
    backend.open()
    assert len(backend.poll(0)) + backend.stats["malformed"] == 2


def test_unrepresentable_times_never_break_output():
    from daybreak.models import format_local, iso_utc

    for ts in (1e13, -1e13, float("inf"), float("nan")):
        assert format_local(ts) == "invalid-time" and iso_utc(ts) == "invalid-time"


def test_lone_surrogates_are_stored_cleaned(tmp_path):
    from daybreak.models import Event

    db = Database(tmp_path / "s.db")
    ev = Event.from_json('{"timestamp": 1790000000, "event_type": "deauth", "bssid": "aa:bb:cc:dd:ee:ff", '
                         '"sensor": "\\ud800x", "metadata": {"note": "\\udfff"}}')
    db.insert_event(ev)
    row = db.query_events()[0]
    assert row["sensor"] == "?x" and row["metadata"]["note"] == "?"
    db.close()


def test_failed_database_writes_are_dropped_and_counted(tmp_path, monkeypatch):
    import sqlite3

    from daybreak.models import Event
    from daybreak.runtime import build_runtime

    rt = build_runtime(make_config(tmp_path))

    def refuse(events):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(rt.db, "insert_events", refuse)
    rt.pipeline.process(Event.from_dict({"ts": 1_790_000_000, "type": "deauth", "bssid": "AA:BB:CC:DD:EE:FF",
                                         "src": "AA:BB:CC:DD:EE:FF", "dst": "10:22:33:44:55:66", "reason": 7}))
    rt.pipeline.flush()
    rt.pipeline.flush()  # nothing left to retry
    assert rt.pipeline.stats["storage_errors"] == 1
    rt.close()


def test_kismet_open_failure_is_a_backend_outage():
    from daybreak.config import KismetConfig
    from daybreak.sensor.backend import BackendUnavailable
    from daybreak.sensor.kismet import KismetBackend, KismetUnavailable

    class Client:
        base, api_key = "http://127.0.0.1:2501", None

        def auth_headers(self):
            return {}

        def system_status(self):
            return {"kismet.system.version": "test"}

        def server_time(self, status=None):
            return 1_790_000_000.0

        def datasources(self):
            raise KismetUnavailable("timed out")

    backend = KismetBackend(KismetConfig(use_eventbus=False, frame_tap=False), sensor_interface=ALFA, client=Client())
    with pytest.raises(BackendUnavailable, match="timed out"):
        backend.open()


def test_text_report_escapes_control_characters():
    from daybreak.report import render_report

    rep = {"period": {"since": 1_790_000_000, "until": 1_790_000_600}, "threat_level": "NORMAL",
           "sensor": {"interface": "wlan\x1b[2J0", "status": []},
           "alerts": {"total": 0, "by_severity": {}, "by_type": {}, "acknowledged": 0, "important": []},
           "events": {}, "networks": [], "baselines": [], "recommendations": []}
    text = render_report(rep)
    assert "\x1b" not in text and "\\x1b[2J" in text


def test_baseline_rates_use_a_bounded_window(tmp_path):
    import time

    from daybreak.baseline.engine import BaselineBuilder
    from daybreak.models import Event, EventType

    b = BaselineBuilder(make_config(tmp_path))
    for ts in (1.0, 1_790_000_000.0):  # a stray event decades before the real one
        b.add(Event(ts, EventType.DEAUTH, bssid="AA:BB:CC:DD:EE:FF", source="AA:BB:CC:DD:EE:FF",
                    destination="10:22:33:44:55:66"))
    started = time.monotonic()
    b.metrics()
    assert time.monotonic() - started < 5.0


def test_incident_bookkeeping_is_bounded(tmp_path):
    from daybreak.correlation.engine import MAX_TRACKED, Incident

    inc = Incident(key="bssid:x", kind="bssid", opened=1.0, last_update=1.0)
    for i in range(MAX_TRACKED * 2):
        inc.note_disconnect(f"10:00:00:00:{i >> 8 & 255:02X}:{i & 255:02X}", 1.0 + i)
    assert len(inc.disconnected) == MAX_TRACKED


def test_low_severity_flood_cannot_starve_a_high_alert_on_the_console():
    import io

    from daybreak.alerts.console import ConsoleNotifier
    from daybreak.alerts.manager import AlertManager
    from daybreak.models import Alert, ScoreComponent

    out = io.StringIO()
    manager = AlertManager([ConsoleNotifier("LOW", stream=out, color=False)], rate_limit_per_minute=5)
    for i in range(50):  # decoys: distinct LOW alerts
        manager.submit(Alert("DEAUTH_BURST", 1_790_000_000.0 + i * 0.1, 30, [ScoreComponent(30, "burst", "")],
                             bssid=f"02:00:00:00:00:{i:02X}", summary="decoy"))
    manager.submit(Alert("POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT", 1_790_000_006.0, 95,
                         [ScoreComponent(95, "pattern", "")], bssid="AA:BB:CC:DD:EE:FF", summary="real"))
    assert "CRITICAL POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT" in out.getvalue()
