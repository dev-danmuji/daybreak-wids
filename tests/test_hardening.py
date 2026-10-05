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
    monkeypatch.setattr(fileperm, "_parent_owner", lambda path: 4242)  # a directory of the sudo user
    fileperm.secure_path(tmp_path / "f")
    fileperm.secure_path(tmp_path / "link")   # O_NOFOLLOW: the link is not followed
    assert chowned == [(str(tmp_path / "f"), 4242, 4343)]
    chowned.clear()
    monkeypatch.setattr(fileperm, "_parent_owner", lambda path: 0)     # e.g. a file a config put into /etc
    fileperm.secure_path(tmp_path / "f")
    assert chowned == []
    monkeypatch.setattr(fileperm, "_parent_owner", lambda path: 4242)
    os.link(tmp_path / "f", tmp_path / "hard")                          # a hard link to another file
    fileperm.secure_path(tmp_path / "hard")
    assert chowned == []
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
    assert sensor_identity_problem(cfg, connected, require_disconnected=False) is None  # identity only
    associated = NS(**{**idle.__dict__, "ssid": "SomeNetwork"})
    assert "associated" in sensor_identity_problem(cfg, associated, require_disconnected=True)
    internal = NS(mac="02:00:00:00:00:01", driver="iwlwifi", nm_state="disconnected", iftype="managed", ssid=None)
    assert "MAC" in sensor_identity_problem(cfg, internal, require_disconnected=False)
    no_mac = make_config(tmp_path, sensor={"interface": "wlo2"}).sensor   # expected_driver stays mt7921u
    assert "driver" in sensor_identity_problem(no_mac, internal, require_disconnected=False)


@pytest.mark.parametrize("args", [["prepare", "--apply", "--channel", "36"], ["release", "--apply"]])
def test_cli_prepare_and_release_refuse_a_connected_sensor(tmp_path, monkeypatch, args):
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
    r = CliRunner().invoke(cli.main, ["-c", str(path), "sensor", *args])  # release would take it down first
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
        backend, events = _read_capture(tmp_path / name)  # ends, never loops or raises mid-file
        assert backend.finished and backend.input_error, name
    backend, events = _read_capture(tmp_path / "epb_too_short")
    assert len(events) == 1  # frames before the corrupt block are kept
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


# -- second review round: fix verification follow-ups ---------------------------------------------------------

def test_interface_names_follow_kernel_rules():
    from daybreak.safety import valid_ifname

    for good in ("wlo1", "wlx00c0cab85c32", "wl#guest", "wlan0.100", "mon@phy0", "149"):
        assert valid_ifname(good), good
    for bad in ("", ".", "..", "-h", "a/b", "a:b", "a b", "tab\tx", "nul\x00", "a" * 16, None, 7):
        assert not valid_ifname(bad), bad


def test_protected_snapshot_runs_nmcli_once(tmp_path):
    fs, route = host_sysfs(tmp_path)
    fs.add_wireless("wlo2", phy="phy0", mac="02:00:00:00:00:02", driver="iwlwifi")  # PHY sibling of wlo1
    runner = host_runner()
    guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=runner)
    snaps = guard.snapshot_protected()
    assert set(snaps) == {"wlo1", "wlo2"}
    assert sum(1 for argv in runner.history if argv[0] == "nmcli") == 1


def test_snapshot_compare_includes_the_phy():
    before = InterfaceSnapshot("wlo1", True, phy="phy0")
    after = InterfaceSnapshot("wlo1", True, phy="phy7")
    assert before.compare(after) == ["phy: 'phy0' -> 'phy7'"]


def test_release_warns_but_prepare_refuses_when_a_protected_interface_is_missing(tmp_path, monkeypatch):
    import yaml
    from click.testing import CliRunner

    import daybreak.sensor.discovery as discovery

    fs, route = host_sysfs(tmp_path)
    runners = []

    def runner_factory(dry_run=False, timeout=10.0):
        r = host_runner(dry_run=dry_run)
        runners.append(r)
        return r

    original = discovery.Discovery

    class FakeDiscovery(original):
        def __init__(self, runner=None, **kw):
            super().__init__(runner, sysfs_root=fs.net, route_file=route)

    monkeypatch.setattr(cli, "CommandRunner", runner_factory)
    monkeypatch.setattr(cli, "InterfaceGuard", lambda *a, **kw: InterfaceGuard(*a, sysfs_root=fs.net,
                                                                               route_file=route, **kw))
    monkeypatch.setattr(discovery, "Discovery", FakeDiscovery)
    monkeypatch.setattr(discovery, "capability_effective", lambda *a, **kw: {"CAP_NET_ADMIN", "CAP_NET_RAW"})
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump({"sensor": {"protected_interfaces": ["wlo1", "wlo9"]}}))
    r = CliRunner().invoke(cli.main, ["-c", str(path), "sensor", "release", "--apply"])
    assert r.exit_code == 0 and "warning: protected interface(s) wlo9 not found" in r.output
    assert any(rr.executed for rr in runners)                      # the sensor was handed back
    r = CliRunner().invoke(cli.main, ["-c", str(path), "sensor", "prepare", "--apply"])
    assert r.exit_code == 1 and "wlo9 not found" in r.output


def test_recovery_needs_all_protected_interfaces_and_a_full_identity(tmp_path):
    fs, route = host_sysfs(tmp_path)
    guard = InterfaceGuard(["wlo1", "wlo9"], sysfs_root=fs.net, route_file=route, runner=host_runner())
    cfg = make_config(tmp_path, sensor={"interface": ALFA, "expected_mac": ALFA_MAC})
    idle = NS(mac=ALFA_MAC.lower(), driver="mt7921u", nm_state="disconnected", iftype="managed", ssid=None)
    assert "wlo9" in cli.SensorRecovery(cfg, guard, runner=None).problem(ALFA, idle)
    no_driver = make_config(tmp_path, sensor={"interface": ALFA, "expected_mac": ALFA_MAC, "expected_driver": None})
    assert "expected_driver" in cli.SensorRecovery(no_driver, None, None).problem("wlan5", idle)
    assert cli.SensorRecovery(no_driver, None, None).problem(ALFA, idle) is None  # same name: fine


def test_recovery_changes_are_alerted_and_auto_prepare_resumes_after_restoration(tmp_path):
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
    clock.at(12, lambda: setattr(guard, "state", "connecting"))
    clock.at(25, lambda: setattr(guard, "state", "connected"))
    runner = MonitorRunner(rt, FakeBackend([]), duration=40, clock=clock, sleep=lambda s: None,
                           guard=guard, recover=lambda iface: True)
    runner.run()
    statuses = [r["status"] for r in rt.db.latest_sensor_status(limit=10)]
    assert "PROTECTED_CHANGED" in statuses and "PROTECTED_RESTORED" in statuses
    assert runner.recover is not None                 # resumed once wlo1 was back to its state at start

    class Recovery:
        last_protected_changes = {"wlo1": ["nm_state: 'connected' -> 'disconnected'"]}

        def __call__(self, iface):
            return False

    from daybreak.sensor.status import HealthTransition

    rt2 = runtime(tmp_path / "second")
    runner2 = MonitorRunner(rt2, FakeBackend([]), duration=1, clock=FakeClock(start=T0), sleep=lambda s: None,
                            recover=Recovery())
    runner2._transition(HealthTransition("SENSOR_RECOVERED", T0, ALFA, ALFA_MAC))
    assert rt2.db.list_alerts(alert_type="PROTECTED_INTERFACE_CHANGED")
    rt.close()
    rt2.close()


@pytest.mark.parametrize("status", [404, 500])
def test_any_http_answer_at_the_kismet_url_prevents_the_fallback(tmp_path, status):
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    try:
        cfg = make_config(tmp_path, backend={"type": "auto", "kismet": {
            "url": f"http://127.0.0.1:{server.server_address[1]}", "timeout": 2}})
        fs, route = host_sysfs(tmp_path)
        runner = host_runner()
        guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=runner)
        with pytest.raises(ValueError, match="will not fall back"):
            choose_backend(cfg, guard=guard, runner=runner, log=lambda m: None)
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("section", [{"sensor": {"dwell_time": 0.01}}, {"sensor": {"health_check_interval": 0.2}},
                                     {"sensor": {"dwell_time": float("inf")}}])
def test_sensor_intervals_have_minimums(tmp_path, section):
    with pytest.raises(ConfigError, match="at least"):
        config_from_dict(section, base_dir=tmp_path)


def test_smoke_script_backgrounds_sudo_itself():
    from pathlib import Path

    script = (Path(__file__).resolve().parents[1] / "scripts" / "hardware-smoke-test.sh").read_text()
    assert 'sudo "$DAYBREAK" -c "$CONFIG" monitor start --backend passive' in script
    assert "sdb monitor start" not in script  # a backgrounded shell function would ignore SIGINT


# -- dashboard: Host names, bind addresses, bounded queries (fix verification, round 3) ---------------

@pytest.mark.parametrize("entry", ["*", "*.lan", "*lan", "wids.lan:8765", "http://wids.lan", "a b", "user@wids.lan",
                                   "127.1", "", "wids..lan", "-wids.lan", "[::1]:8765"])
def test_allowed_hosts_must_be_literal_names(tmp_path, entry):
    with pytest.raises(ConfigError, match="allowed_hosts"):
        make_config(tmp_path, dashboard={"host": "0.0.0.0", "allow_remote": True, "allowed_hosts": [entry]})


def test_allowed_hosts_are_normalised_and_still_exclusive(tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from daybreak.dashboard.app import create_app

    cfg = make_config(tmp_path, dashboard={"host": "0.0.0.0", "allow_remote": True,
                                           "allowed_hosts": ["WIDS.Lan", "[::1]", "192.168.1.10", "wids.lan"]})
    assert cfg.dashboard.allowed_hosts == ["wids.lan", "::1", "192.168.1.10"]
    app = create_app(cfg, allow_remote=True, bind_host="0.0.0.0")
    assert TestClient(app, base_url="http://wids.lan:8765").get("/api/status").status_code == 200
    for evil in ("http://evil.lan", "http://attacker.example:8765"):
        assert TestClient(app, base_url=evil).get("/api/status").status_code == 400


@pytest.mark.parametrize("host", ["0", "000.000.000.000", "127.1", "0x7f000001"])
def test_noncanonical_dashboard_addresses_are_refused(tmp_path, host):
    from daybreak.dashboard.app import serve

    with pytest.raises(ConfigError, match="canonical"):
        make_config(tmp_path, dashboard={"host": host, "allow_remote": True})
    cfg = make_config(tmp_path, dashboard={"allow_remote": True, "allowed_hosts": ["wids.lan"]})
    with pytest.raises(ValueError, match="canonical"):
        serve(cfg, host=host, port=8765, allow_remote=True)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "[::]", "::0", "0:0:0:0:0:0:0:0", ""])
def test_every_spelling_of_all_interfaces_needs_allowed_hosts(tmp_path, host):
    from daybreak.config import is_unspecified_host
    from daybreak.dashboard.app import LOOPBACK_HOSTS, allowed_hosts, serve

    assert is_unspecified_host(host)
    with pytest.raises(ValueError, match="allowed_hosts"):
        serve(make_config(tmp_path, dashboard={"allow_remote": True}), host=host, port=8765, allow_remote=True)
    cfg = make_config(tmp_path, dashboard={"allow_remote": True, "allowed_hosts": ["wids.lan"]})
    assert allowed_hosts(cfg, host, allow_remote=True) == [*LOOPBACK_HOSTS, "wids.lan"]  # never the wildcard


def test_dashboard_is_get_only_and_bounds_requests_in_flight(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    import uvicorn
    from fastapi.testclient import TestClient

    import daybreak.dashboard.app as dash

    c = TestClient(dash.create_app(make_config(tmp_path)), base_url="http://127.0.0.1")
    r = c.head("/api/status")
    assert r.status_code == 405 and r.headers["allow"] == "GET"
    monkeypatch.setattr(dash, "MAX_IN_FLIGHT", 0)
    r = c.get("/api/status")
    assert r.status_code == 503 and r.headers["retry-after"] == "1"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    seen = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw))
    dash.serve(make_config(tmp_path), host="127.0.0.1", port=8765)
    assert seen["host"] == "127.0.0.1" and "limit_concurrency" not in seen  # idle sockets cannot block it


def test_registered_ap_is_listed_despite_a_stale_flag_and_a_flood(tmp_path):
    pytest.importorskip("fastapi")
    import time

    from fastapi.testclient import TestClient

    from conftest import HOME_BSSID
    from daybreak.dashboard.app import create_app
    from daybreak.models import Event

    cfg = make_config(tmp_path)
    db = Database(cfg.database_path)
    t0 = time.time() - 600
    weak = Event.from_dict({"ts": t0, "type": "beacon", "bssid": HOME_BSSID, "ssid": "ExampleSSID",
                            "security": {"akms": ["PSK"], "pmf": "disabled"}}).security
    # written while the network was not yet registered: authorized=0 in the row
    db.upsert_ap(bssid=HOME_BSSID, ssid="ExampleSSID", network_id=None, authorized=False, channel=36,
                 security=weak, phy=None, rssi=-40, timestamp=t0)
    for i in range(60):  # more recently heard unregistered BSSIDs
        db.upsert_ap(bssid=f"02:00:00:00:00:{i:02X}", ssid="ExampleSSID", network_id=None, authorized=False,
                     channel=36, security=None, phy=None, rssi=-70, timestamp=t0 + 60 + i)
    rows = db.list_aps(ssid="ExampleSSID", registered=[HOME_BSSID], limit=50)
    assert rows[0]["bssid"] == HOME_BSSID and len(rows) == 51
    db.close()
    home = TestClient(create_app(cfg), base_url="http://127.0.0.1").get("/api/networks").json()[0]
    assert home["mode"] == "WPA2-PSK" and HOME_BSSID in str(home["aps"])
    assert home["unknown_bssid_count"] == 60 and len(home["unknown_bssids"]) <= 50


def test_alerts_store_and_log_a_bounded_station_list(tmp_path):
    from daybreak.alerts.formatting import human_text
    from daybreak.models import MAX_ALERT_LIST, Alert, ScoreComponent

    stations = tuple(f"10:00:00:00:{i >> 8 & 255:02X}:{i & 255:02X}" for i in range(5000))
    a = Alert("MULTI_CLIENT_DEAUTH", 1_790_000_000.0, 40, [ScoreComponent(40, "x", "", "deauth")],
              stations=stations, details={"rogue_bssids": ["02:00:00:00:00:01"], "rogue_bssid_count": 9})
    for form in (a.reason_dict(), a.to_dict()):
        assert len(form["stations"]) == MAX_ALERT_LIST and form["stations_total"] == 5000
    db = Database(tmp_path / "a.db")
    db.insert_alert(a)
    assert db.conn.execute("SELECT length(reason_json) FROM alerts").fetchone()[0] < 4000
    assert "Stations=5000" in human_text(a) and "(+8 more)" in human_text(a)
    light = db.list_alerts(with_reason=False)
    assert "reason" not in light[0] and light[0]["severity"] == "LOW"
    db.close()


def test_random_station_and_bssid_floods_keep_alert_rows_small(tmp_path):
    from conftest import HOME_BSSID
    from daybreak.models import Event, EventType
    from daybreak.runtime import build_runtime

    rt = build_runtime(make_config(tmp_path))
    p = rt.pipeline
    t0 = 1_790_000_000.0
    for i in range(6000):  # 300 unicast deauths/s for 20 s, each to a new random station
        p.process(Event.from_dict({"ts": t0 + i / 300, "type": "deauth", "bssid": HOME_BSSID, "src": HOME_BSSID,
                                   "dst": f"02:10:00:{i >> 16 & 255:02X}:{i >> 8 & 255:02X}:{i & 255:02X}",
                                   "reason": 7, "seq": i % 4096}))
    for i in range(3000):  # then beacons for the protected SSID from random BSSIDs
        p.process(Event(t0 + 30 + i * 0.01, EventType.BEACON, ssid="ExampleSSID", channel=36,
                        bssid=f"02:20:00:{i >> 16 & 255:02X}:{i >> 8 & 255:02X}:{i & 255:02X}"))
    p.flush()
    sizes = dict(rt.db.conn.execute("SELECT alert_type, MAX(length(reason_json)) FROM alerts GROUP BY alert_type"))
    assert {"MULTI_CLIENT_DEAUTH", "POSSIBLE_DEAUTH_ATTACK"} <= set(sizes)
    assert max(sizes.values()) < 8000, sizes
    rt.close()


def test_random_ssid_flood_is_bounded_and_ap_lookups_use_an_index(tmp_path):
    from daybreak.models import Event, EventType
    from daybreak.pipeline import UNKNOWN_AP_ROWS_TOTAL_PER_HOUR
    from daybreak.runtime import build_runtime

    rt = build_runtime(make_config(tmp_path, detection={"scope": "all"}))
    t0 = 1_790_000_000.0
    for i in range(3000):  # 100 beacons/s for 30 s, each a new BSSID with a new SSID
        rt.pipeline.process(Event(t0 + i * 0.01, EventType.BEACON, ssid=f"rnd-{i}", channel=36,
                                  bssid=f"02:30:00:{i >> 16 & 255:02X}:{i >> 8 & 255:02X}:{i & 255:02X}"))
    rt.pipeline.flush()
    rows = rt.db.conn.execute("SELECT COUNT(*) FROM aps").fetchone()[0]
    assert rows <= UNKNOWN_AP_ROWS_TOTAL_PER_HOUR + 30 * UNKNOWN_AP_ROWS_TOTAL_PER_HOUR / 3600 + 1
    assert rt.pipeline.stats["aps_not_stored"] == 3000 - rows
    plan = " ".join(str(r[-1]) for r in rt.db.conn.execute(
        "EXPLAIN QUERY PLAN SELECT * FROM aps WHERE ssid = ? AND bssid NOT IN (?) ORDER BY last_seen DESC LIMIT 50",
        ("ExampleSSID", "AA:BB:CC:DD:EE:FF")))
    assert "idx_aps_ssid_last_seen" in plan
    rt.close()


def test_readonly_open_reports_empty_foreign_or_pending_databases(tmp_path):
    import sqlite3

    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from daybreak.dashboard.app import create_app

    empty = tmp_path / "empty.db"
    empty.write_bytes(b"")
    foreign = tmp_path / "foreign.db"
    with sqlite3.connect(foreign) as conn:
        conn.execute("CREATE TABLE notes (x)")
    for path in (empty, foreign):
        with pytest.raises(sqlite3.DatabaseError, match="daybreak-wids database"):
            Database(path, readonly=True)
    cfg = make_config(tmp_path, storage={"database": str(empty)})
    c = TestClient(create_app(cfg), base_url="http://127.0.0.1")
    assert c.get("/api/status").json()["database"] == "unreadable"
    assert c.get("/api/alerts").status_code == 503 and c.get("/api/networks").status_code == 503


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_readonly_open_never_serves_old_data_while_a_wal_is_pending(tmp_path):
    import shutil
    import sqlite3

    src = tmp_path / "live"
    db = Database(src / "w.db")
    db.conn.execute("PRAGMA wal_autocheckpoint = 0")
    db.sync_networks(make_config(tmp_path).protected_networks)  # committed, but only in w.db-wal
    snap = tmp_path / "snap"
    snap.mkdir()
    for name in ("w.db", "w.db-wal"):  # as left by a root monitor that died: no -shm, directory not writable
        shutil.copy(src / name, snap / name)
    db.close()
    assert (snap / "w.db-wal").stat().st_size > 0
    clean = tmp_path / "clean"  # after a clean stop everything is checkpointed into w.db
    clean.mkdir()
    shutil.copy(src / "w.db", clean / "w.db")
    for d in (snap, clean):
        d.chmod(0o555)
    try:
        with pytest.raises(sqlite3.Error):
            Database(snap / "w.db", readonly=True)
        ro = Database(clean / "w.db", readonly=True)  # nothing pending: the immutable fallback is accurate
        assert [n["name"] for n in ro.list_networks()] == ["home", "lab"]
        ro.close()
    finally:
        for d in (snap, clean):
            d.chmod(0o755)


# -- fix verification, round 4: sensor use, Kismet input, config, output ------------------------------------

@pytest.mark.parametrize("iftype", ["AP", "P2P-GO", "IBSS", "mesh point"])
def test_a_sensor_serving_or_joining_a_network_is_in_use(tmp_path, iftype):
    from daybreak.sensor.control import sensor_identity_problem

    cfg = make_config(tmp_path, sensor={"interface": ALFA, "expected_mac": ALFA_MAC}).sensor
    hotspot = NS(mac=ALFA_MAC, driver="mt7921u", nm_state="unmanaged", iftype=iftype, ssid="MyHotspot")
    assert f"{iftype} mode" in sensor_identity_problem(cfg, hotspot, require_disconnected=True)
    monitor = NS(**{**hotspot.__dict__, "iftype": "monitor", "ssid": None})
    assert sensor_identity_problem(cfg, monitor, require_disconnected=True) is None  # what release expects


def test_read_only_commands_cannot_be_declared_interface_changing():
    guard = NS(assert_may_modify=lambda iface: None)
    with pytest.raises(SafetyViolation, match="not an interface-changing command"):
        safety.checked_command(["iw", "dev", ALFA, "info"], mutating=True, guard=guard)


def test_the_host_command_allow_list_is_pinned():
    # Widening the runtime allow-list must show up as a test change in review: e.g. `iw dev X scan`
    # or `iw dev X connect` would make the adapter transmit.
    assert {e.pattern for e in safety.COMMAND_ALLOW_LIST} == {
        ("iw", "phy", None, "info"),
        ("iw", "dev", None, "info"),
        ("iw", "reg", "get"),
        ("iw", "dev", None, "set", "type", frozenset({"monitor", "managed"})),
        ("iw", "dev", None, "set", "channel", None),
        ("ip", "link", "set", None, frozenset({"up", "down"})),
        ("nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status"),
        ("nmcli", "-t", "-f", "DEVICE,STATE", "device", "status"),
        ("nmcli", "device", "set", None, "managed", frozenset({"yes", "no"})),
    }


def test_kismet_alert_fields_are_strings_identifiers_and_plausible_times():
    from daybreak.sensor.kismet import alert_to_event

    def rec(**over):
        base = {"kismet.alert.header": "DEAUTHFLOOD", "kismet.alert.timestamp": 1_790_000_000.5,
                "kismet.alert.transmitter_mac": "AA:BB:CC:DD:EE:FF", "kismet.alert.text": "flood"}
        return {**base, **over}

    nested = alert_to_event(rec(**{"kismet.alert.text": {"anonce": "ab" * 32, "mic": "cd" * 16},
                                   "kismet.alert.class": {"x": 1}}), "s")
    assert "kismet_text" not in nested.metadata and "kismet_class" not in nested.metadata
    assert alert_to_event(rec(**{"kismet.alert.header": {"h": 1}}), "s") is None
    assert alert_to_event(rec(**{"kismet.alert.header": "CRYPTODROP\x1b[31m"}), "s").metadata["kismet_header"] == "OTHER"
    assert alert_to_event(rec(**{"kismet.alert.header": "x" * 65}), "s").metadata["kismet_header"] == "OTHER"
    for ts in (1e13, -5.0, float("nan")):
        assert alert_to_event(rec(**{"kismet.alert.timestamp": ts}), "s") is None


def test_replayed_kismet_headers_cannot_inject_into_alert_types(tmp_path):
    from daybreak.detectors.base import DetectionContext
    from daybreak.detectors.kismet_alerts import KismetAlertDetector
    from daybreak.models import Event
    from daybreak.registry import NetworkRegistry

    cfg = make_config(tmp_path)
    ctx = DetectionContext(cfg, NetworkRegistry(cfg.protected_networks))
    ev = Event.from_dict({"ts": 1_790_000_000.0, "type": "kismet_alert", "bssid": "AA:BB:CC:DD:EE:FF",
                          "kismet_header": "CRYPTODROP\x1b[2J"})
    assert [f.finding_type for f in KismetAlertDetector().process(ev, ctx)] == ["KISMET_OTHER"]


def test_an_implausible_kismet_clock_does_not_wedge_alert_polling():
    from daybreak.config import KismetConfig
    from daybreak.sensor.kismet import KismetBackend

    class Client:
        base = "http://127.0.0.1:2501"

        def system_status(self):
            return {"kismet.system.version": "x", "kismet.system.timestamp.sec": 1e13}

        def server_time(self, st):
            return 1e13

        def datasources(self):
            return []

        def auth_headers(self):
            return {}

    b = KismetBackend(KismetConfig(use_eventbus=False, frame_tap=False), sensor_interface=ALFA, client=Client(),
                      clock=lambda: 1_790_000_000.0)
    b.open()
    assert b.last_alert_ts == 1_790_000_000.0


@pytest.mark.parametrize("section, match", [
    ({"sensor": {"protected_interfaces": []}}, "must not be empty"),
    ({"backend": {"kismet": {"api_key_env": "4C3B9F0A1D2E3F4A5B6C7D8E9F0A1B2C"}}}, "not the secret"),
    ({"backend": {"kismet": {"api_key_env": "ABCDEF0123456789ABCDEF0123456789"}}}, "not the secret"),
    ({"backend": {"kismet": {"password_env": "my password"}}}, "not the secret"),
    ({"logging": {"human_log": "/var/log/daybreak/daybreak.log"}}, "file name inside"),
    ({"logging": {"jsonl_log": "sub/alerts.jsonl"}}, "file name inside"),
    ({"alerts": {"notifiers": [{"type": "jsonl", "options": {"psk": "x"}}]}}, "looks like a secret"),
])
def test_config_rejects_unsafe_values_at_load(tmp_path, section, match):
    with pytest.raises(ConfigError, match=match):
        config_from_dict(section, base_dir=tmp_path)


def test_retention_failures_do_not_stop_the_monitor(tmp_path):
    import sqlite3

    from daybreak.monitor import MonitorRunner

    said = []
    runner = MonitorRunner.__new__(MonitorRunner)
    runner.cfg = make_config(tmp_path)
    runner.rt = NS(db=NS(prune=lambda older_than: (_ for _ in ()).throw(sqlite3.OperationalError("disk I/O error"))))
    runner.backend = NS(name="passive")
    runner.say = said.append
    runner._prune(1_790_000_000.0)
    assert said and "pruning failed" in said[0]


def test_pruned_rows_do_not_linger_in_the_wal(tmp_path):
    from daybreak.models import Event

    db = Database(tmp_path / "w.db")
    old = 1_790_000_000.0 - 90 * 86400
    db.insert_events([Event.from_dict({"ts": old + i, "type": "deauth", "bssid": "AA:BB:CC:DD:EE:FF",
                                       "src": "AA:BB:CC:DD:EE:FF", "dst": "DE:AD:BE:EF:00:01"}) for i in range(50)])
    assert db.prune(older_than=1_790_000_000.0 - 30 * 86400)["events"] == 50
    wal = tmp_path / "w.db-wal"
    assert not wal.exists() or b"\xde\xad\xbe\xef" not in wal.read_bytes() and "DE:AD:BE:EF" not in wal.read_text("latin-1")
    db.close()


def test_invisible_and_line_separator_characters_are_escaped():
    from daybreak.alerts.formatting import printable

    for ch in (" ", " ", "​", "‍", "﻿", "⁠", "؜"):
        assert ch not in printable(f"x{ch}second") and "\\u" in printable(f"x{ch}second")
    assert "x second".splitlines() == ["x second"]
    assert printable("Café ☕") == "Café ☕"


@pytest.mark.parametrize("ssid, text, attributed", [
    ("Bob's WiFi", "IEEE80211 Unauthorized device (02:AA:00:00:00:01) advertising for SSID 'Bob's WiFi', "
                   "matching APSPOOF rule r", True),
    ("home", "advertising for SSID 'home', matching APSPOOF rule", True),
    ("home", 'advertising for SSID "home" on channel 6', True),
    ("home", "advertising for SSID 'myhome', matching", False),
    ("home", "advertising for SSID 'home_2G', matching", False),
    ("home", "advertising for SSID 'a'home'b', matching", False),
])
def test_kismet_texts_are_attributed_by_the_whole_quoted_ssid(tmp_path, ssid, text, attributed):
    from daybreak.models import Event
    from daybreak.registry import NetworkRegistry

    cfg = make_config(tmp_path, protected_networks=[{"name": "n", "ssid": ssid}])
    reg = NetworkRegistry(cfg.protected_networks)
    ev = Event.from_dict({"ts": 1_790_000_000.0, "type": "kismet_alert", "kismet_header": "APSPOOF",
                          "kismet_text": text, "src": "02:AA:00:00:00:01"})
    assert (reg.network_of(ev) is not None) is attributed


def test_cli_output_escapes_relayed_kismet_text(tmp_path):
    import json

    import yaml
    from click.testing import CliRunner

    from daybreak.models import Alert, ScoreComponent
    from daybreak.monitor import status_path

    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump({"storage": {"database": str(tmp_path / "d.db")},
                                    "logging": {"directory": str(tmp_path / "log")}}))
    cfg = cli.load_config(str(path))
    db = Database(cfg.database_path)
    db.insert_alert(Alert("KISMET_X\x1b[2J", 1_790_000_000.0, 10, [ScoreComponent(10, "l", "", "kismet_other")]))
    db.close()
    status_path(cfg).parent.mkdir(parents=True, exist_ok=True)
    status_path(cfg).write_text(json.dumps({"state": "running", "updated": 1_790_000_000.0, "pid": 1,
                                            "backend": {"name": "kismet", "detail": "Kismet\x1b]0;pwned\x07"}}))
    for args in (["alerts", "--since", "100000d"], ["monitor", "status"]):
        out = CliRunner().invoke(cli.main, ["-c", str(path), *args]).output
        assert "\x1b" not in out and "\x07" not in out, args


def test_monitor_start_says_when_desktop_notifications_are_off(tmp_path, monkeypatch):
    import yaml
    from click.testing import CliRunner

    from daybreak.alerts import desktop

    monkeypatch.setattr(desktop.os, "geteuid", lambda: 0)
    fixture = os.path.join(os.path.dirname(__file__), "fixtures", "normal.jsonl")
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump({"storage": {"database": str(tmp_path / "d.db")},
                                    "logging": {"directory": str(tmp_path / "log")},
                                    "alerts": {"notifiers": [{"type": "desktop"}]}}))
    r = CliRunner().invoke(cli.main, ["-c", str(path), "monitor", "start", "--replay", fixture, "--quiet"])
    assert r.exit_code == 0 and "desktop notifications off: running as root" in r.output


def test_monitor_start_warns_about_plain_http_credentials(tmp_path, monkeypatch):
    from daybreak.sensor.kismet import KismetUnavailable

    monkeypatch.setenv("DAYBREAK_TEST_PLAIN_KEY", "k")
    cfg = make_config(tmp_path, backend={"type": "auto", "kismet": {"url": "http://192.0.2.10:2501",
                                                                     "api_key_env": "DAYBREAK_TEST_PLAIN_KEY"}})
    logged = []
    import daybreak.sensor.kismet as kismet_mod

    monkeypatch.setattr(kismet_mod.KismetClient, "system_status",
                        lambda self: (_ for _ in ()).throw(KismetUnavailable("not reachable")))
    fs, route = host_sysfs(tmp_path)
    guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=host_runner())
    choose_backend(cfg, guard=guard, runner=host_runner(), log=logged.append)
    assert any("unencrypted" in m for m in logged)


# -- fix verification, round 5: robustness of parsing and long runs ----------------------------------------

def _deauth_dict(ts, bssid="AA:BB:CC:DD:EE:FF", dst="10:22:33:44:55:01"):
    return {"ts": ts, "type": "deauth", "bssid": bssid, "src": bssid, "dst": dst, "reason": 7, "channel": 36}


def _deauth(ts, bssid="AA:BB:CC:DD:EE:FF", dst="10:22:33:44:55:01"):
    from daybreak.models import Event

    return Event.from_dict(_deauth_dict(ts, bssid, dst))


def test_one_future_timestamp_cannot_hold_the_window_open(tmp_path):
    from daybreak.detectors.window import SlidingWindow
    from daybreak.runtime import build_runtime

    w = SlidingWindow(5.0)
    w.add(1000.0 + 3600)  # a stray frame one hour ahead
    for t in range(10):
        w.add(1000.0 + t * 30)
    assert w.count(1000.0 + 9 * 30) == 1
    # the verifier's case: benign disconnects 30 s apart after one future-stamped frame
    rt = build_runtime(make_config(tmp_path), dry_run=True)
    t0 = 1_790_000_000.0
    rt.pipeline.process(_deauth(t0 + 3600))
    for i in range(40):
        rt.pipeline.process(_deauth(t0 + i * 30, dst=f"10:22:33:44:55:{i:02X}"))
    assert not [a for a in rt.alerts.delivered if a.alert_type in ("DEAUTH_BURST", "MULTI_CLIENT_DEAUTH",
                                                                   "POSSIBLE_DEAUTH_ATTACK")]
    rt.close()


def test_keyed_state_is_capped_and_keeps_registered_keys():
    from daybreak.detectors.window import KeyedState

    ks = KeyedState(dict, max_keys=100, keep=lambda k: k == "home")
    ks.get("home", 0.0)
    for i in range(10_000):
        ks.get(f"rnd{i}", 1.0)
    assert len(ks) == 100 and "home" in ks and f"rnd{9_999}" in ks


def test_random_bssid_flood_cannot_evict_the_protected_bssid_or_grow_state(tmp_path):
    from daybreak.runtime import build_runtime

    rt = build_runtime(make_config(tmp_path), dry_run=True)
    p = rt.pipeline
    t0 = 1_790_000_000.0
    for i in range(6):  # half a burst against the protected AP ...
        p.process(_deauth(t0 + i * 0.1, dst=f"10:22:33:44:55:{i:02X}"))
    for i in range(30_000):  # ... then a flood from random BSSIDs, all with the same timestamp ...
        p.process(_deauth(t0 + 0.6, bssid=f"02:40:{i >> 16 & 255:02X}:{i >> 8 & 255:02X}:{i & 255:02X}:01",
                          dst="AA:BB:CC:DD:EE:FF"))
    deauth = next(d for d in p.detectors if d.name == "deauth")
    assert len(deauth.state) <= deauth.state.max_keys
    assert len(p.correlator.incidents) <= 4096
    for i in range(6):  # ... and the rest of the burst: the protected AP's window survived the flood
        p.process(_deauth(t0 + 0.7 + i * 0.1, dst=f"10:22:33:44:55:{i + 6:02X}"))
    assert any(a.alert_type == "DEAUTH_BURST" and a.network == "home" for a in rt.alerts.delivered)
    rt.close()


def test_alert_rows_for_random_bssids_are_bounded_but_protected_alerts_are_not(tmp_path):
    from daybreak.alerts.manager import NEW_UNPROTECTED_SCOPES_PER_MINUTE, AlertManager
    from daybreak.models import Alert, ScoreComponent

    db = Database(tmp_path / "a.db")
    manager = AlertManager([], db=db)
    t0 = 1_790_000_000.0
    for i in range(5000):
        manager.submit(Alert("DEAUTH_BURST", t0 + i * 0.01, 30, [ScoreComponent(30, "burst", "")],
                             bssid=f"02:00:00:00:{i >> 8 & 255:02X}:{i & 255:02X}"))
    stored = db.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    allowed = NEW_UNPROTECTED_SCOPES_PER_MINUTE * (1 + 50 / 60)  # burst plus refill over the 50 s flood
    assert stored <= allowed + 1 and manager.stats["flood_suppressed"] == 5000 - stored
    assert manager.submit(Alert("DEAUTH_BURST", t0 + 60, 30, [ScoreComponent(30, "burst", "")],
                                bssid="AA:BB:CC:DD:EE:FF", network="home"))
    db.close()


def test_alert_and_sensor_status_write_failures_do_not_stop_detection(tmp_path):
    import io
    import sqlite3

    from daybreak.alerts.console import ConsoleNotifier
    from daybreak.alerts.manager import AlertManager
    from daybreak.models import Alert, Event, ScoreComponent
    from daybreak.runtime import build_runtime

    def fail(*a, **kw):
        raise sqlite3.OperationalError("database or disk is full")

    out = io.StringIO()
    manager = AlertManager([ConsoleNotifier("LOW", stream=out, color=False)], db=NS(insert_alert=fail))
    assert manager.submit(Alert("DEAUTH_BURST", 1_790_000_000.0, 50, [ScoreComponent(50, "burst", "")],
                                network="home", bssid="AA:BB:CC:DD:EE:FF"))
    assert "DEAUTH_BURST" in out.getvalue() and manager.stats["storage_errors"] == 1
    rt = build_runtime(make_config(tmp_path))
    rt.db.record_sensor_status = fail
    rt.pipeline.process(Event.from_dict({"ts": 1_790_000_000.0, "type": "sensor", "status": "lost"}))
    assert rt.pipeline.stats["storage_errors"] == 1
    rt.close()


def test_the_monitor_survives_an_event_that_fails_to_process(tmp_path):
    import json

    from daybreak.monitor import MonitorRunner
    from daybreak.runtime import build_runtime
    from daybreak.sensor.replay import ReplayBackend

    rt = build_runtime(make_config(tmp_path), dry_run=True)
    real = rt.pipeline.process
    calls = []

    def flaky(ev):
        calls.append(ev)
        if len(calls) == 1:
            raise RuntimeError("bug in a detector")
        return real(ev)

    rt.pipeline.process = flaky
    lines = [json.dumps(_deauth_dict(1_790_000_000.0 + i)) for i in range(3)]
    runner = MonitorRunner(rt, ReplayBackend(lines), write_status=False, on_message=lambda m: None)
    summary = runner.run()
    assert len(calls) == 3 and summary["stats"]["processing_errors"] == 1
    rt.close()


def test_a_corrupt_capture_ends_the_run_instead_of_looping(tmp_path):
    import struct

    import yaml
    from click.testing import CliRunner

    import frames_hex as F

    good = _pcapng(_idb(), _epb(F.RT_5180 + F.DEAUTH_UNICAST, 1_790_000_000_000_000))
    (tmp_path / "cut.pcapng").write_bytes(good + struct.pack("<III", 6, 12, 12))
    (tmp_path / "junk.pcap").write_bytes(b"this is not a capture file at all")
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump({"storage": {"database": str(tmp_path / "d.db")},
                                    "logging": {"directory": str(tmp_path / "log")}, "detection": {"scope": "all"}}))
    r = CliRunner().invoke(cli.main, ["-c", str(path), "--dry-run", "monitor", "start", "--pcap",
                                      str(tmp_path / "cut.pcapng"), "--quiet", "--duration", "20"])
    assert r.exit_code == 0 and "input ended early" in r.output and "processed 1 events" in r.output
    r = CliRunner().invoke(cli.main, ["-c", str(path), "--dry-run", "monitor", "start", "--pcap",
                                      str(tmp_path / "junk.pcap"), "--quiet", "--duration", "20"])
    assert r.exit_code == 1 and "not a pcap/pcapng file" in r.output


def test_replay_files_with_undecodable_bytes_are_read_as_malformed_lines(tmp_path):
    from daybreak.sensor.replay import ReplayBackend

    import json

    good = json.dumps(_deauth_dict(1_790_000_000.0))
    f = tmp_path / "r.jsonl"
    f.write_bytes(good.encode() + b"\n\xff\xfe{\"ts\": 1}\n" + good.encode() + b"\n")
    b = ReplayBackend(f)
    b.open()
    events = []
    while not b.finished:
        events += b.poll(0)
    b.close()
    assert len(events) == 2 and b.stats["malformed"] == 1


def test_kismet_numeric_fields_are_range_checked():
    from daybreak.sensor.kismet import DatasourceInfo, alert_to_event, device_to_event

    alert = {"kismet.alert.header": "DEAUTHFLOOD", "kismet.alert.timestamp": 1_790_000_000.0,
             "kismet.alert.frequency": float("inf")}
    assert "frequency" not in alert_to_event(alert, "s").metadata
    for packets in (float("inf"), "n/a", None):
        DatasourceInfo.from_record({"kismet.datasource.name": "x", "kismet.datasource.num_packets": packets})
    dev = device_to_event({"mac": "AA:BB:CC:DD:EE:FF", "ssid": "x\ud800", "type": "Wi-Fi AP", "crypt_string": "WPA2",
                           "last_time": float("nan"), "frequency": 1e300}, "s", 1_790_000_000.0)
    assert dev.timestamp == 1_790_000_000.0 and dev.ssid == "x?" and "frequency" not in dev.metadata


def test_security_strings_are_cleaned_and_bounded(tmp_path, monkeypatch):
    from daybreak.models import Event

    ev = Event.from_dict({"ts": 1_790_000_000.0, "type": "beacon", "bssid": "AA:BB:CC:DD:EE:FF", "ssid": "x",
                          "security": {"akms": ["\ud800PSK"] * 100, "group_cipher": "C" * 500, "source": "\udfff"}})
    sec = ev.security
    assert sec.akms[0] == "?PSK" and len(sec.akms) == 32 and len(sec.group_cipher) == 64 and sec.source == "?"
    echoed = []
    monkeypatch.setattr(cli.click, "echo", lambda text, **kw: echoed.append(text))
    cli.emit_json({"text": "\ud800"})
    echoed[0].encode("utf-8")  # --json output is always encodable (no UnicodeEncodeError on a terminal)


def test_baseline_candidates_are_bounded(tmp_path):
    from daybreak.baseline.engine import MAX_CANDIDATES, build_from_events
    from daybreak.models import Event, EventType

    cfg = make_config(tmp_path)
    t0 = 1_790_000_000.0
    events = [Event(t0 + i * 0.01, EventType.BEACON, ssid="ExampleSSID", channel=36,
                    bssid=f"02:50:00:{i >> 16 & 255:02X}:{i >> 8 & 255:02X}:{i & 255:02X}") for i in range(5000)]
    home = build_from_events(cfg, events)["home"]
    assert len(home["candidate_bssids"]) == MAX_CANDIDATES and home["candidate_bssid_count"] == 5000


@pytest.mark.parametrize("section", [
    {"detection": {"deauth": {"burst_window": float("nan")}}},
    {"detection": {"correlation": {"window": float("inf")}}},
    {"detection": {"baseline": {"bucket": 1e-9}}},
    {"alerts": {"cooldown": float("nan")}},
])
def test_detection_timing_must_be_finite_and_sane(tmp_path, section):
    with pytest.raises(ConfigError):
        config_from_dict(section, base_dir=tmp_path)


def test_monitor_status_escapes_the_interface_name(tmp_path):
    import json

    import yaml
    from click.testing import CliRunner

    from daybreak.monitor import status_path

    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump({"storage": {"database": str(tmp_path / "d.db")},
                                    "logging": {"directory": str(tmp_path / "log")}}))
    cfg = cli.load_config(str(path))
    status_path(cfg).parent.mkdir(parents=True, exist_ok=True)
    status_path(cfg).write_text(json.dumps({"state": "running", "updated": 1_790_000_000.0, "pid": 1,
                                            "sensor": {"interface": "wlx\x1b]0;pwned\x07", "online": False}}))
    out = CliRunner().invoke(cli.main, ["-c", str(path), "monitor", "status"]).output
    assert "\x1b" not in out and "\x07" not in out
