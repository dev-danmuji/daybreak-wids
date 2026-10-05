import functools
import json

import pytest
import yaml
from click.testing import CliRunner

import daybreak.cli as cli
import daybreak.sensor.discovery as discovery
from conftest import FIXTURES, HOME_BSSID, HOME_BSSID_5G
from daybreak.safety import InterfaceGuard
from helpers import host_runner, host_sysfs


@pytest.fixture
def cfgfile(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({
        "protected_networks": [{"name": "home", "ssid": "ExampleSSID", "bssids": [HOME_BSSID, HOME_BSSID_5G],
                                "channels": [36, 6], "security": {"expected": ["WPA2", "WPA3"], "pmf": "capable"}}],
        "storage": {"database": "var/daybreak.db"},
        "logging": {"directory": "var/log"},
        "alerts": {"notifiers": [{"type": "console", "min_severity": "HIGH"}, {"type": "jsonl"}]},
        "backend": {"kismet": {"url": "http://127.0.0.1:9", "timeout": 1}},
    }))
    return path


def run(cfgfile, *args, input=None):
    result = CliRunner().invoke(cli.main, ["-c", str(cfgfile), *args], input=input, catch_exceptions=False)
    return result


def test_version_and_disclaimer():
    r = CliRunner().invoke(cli.main, ["--help"])
    assert r.exit_code == 0 and "does not implement packet" in r.output
    assert "0.1.0" in CliRunner().invoke(cli.main, ["--version"]).output


def test_unsafe_config_is_refused(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("safety:\n  packet_injection: true\n")
    r = CliRunner().invoke(cli.main, ["-c", str(bad), "network", "list"])
    assert r.exit_code == 1 and "safety" in r.output and "passive" in r.output


def test_replay_pipeline_end_to_end(cfgfile, tmp_path):
    r = run(cfgfile, "monitor", "start", "--replay", str(FIXTURES / "handshake_pattern.jsonl"))
    assert r.exit_code == 0, r.output
    assert "POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT" in r.output and "Risk 95 CRITICAL" in r.output
    assert "Authorized defensive monitoring only" in r.output
    var = tmp_path / "var"
    assert (var / "daybreak.db").exists() and (var / "log" / "alerts.jsonl").exists()
    assert "POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT" in (var / "log" / "daybreak.log").read_text()

    r = run(cfgfile, "alerts", "--since", "3000d", "--severity", "HIGH", "--details")
    assert "POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT" in r.output and "+30 deauth burst" in r.output
    r = run(cfgfile, "--json", "alerts", "--since", "3000d")
    rows = json.loads(r.output)
    first = rows[-1]["id"]
    assert run(cfgfile, "alerts", "--ack", str(first)).output.startswith(f"acknowledged #{first}")

    rep = json.loads(run(cfgfile, "report", "--since", "3000d", "--format", "json").output)
    assert rep["threat_level"] == "CRITICAL" and rep["alerts"]["by_type"]["POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT"]
    assert "DAYBREAK WIDS REPORT" in run(cfgfile, "report", "--since", "3000d").output

    status = run(cfgfile, "monitor", "status").output
    assert "stopped" in status and "processed" in status

    audit = run(cfgfile, "audit", "security").output
    assert "WPA2/WPA3 Transition : enabled" in audit
    policy = run(cfgfile, "audit", "policy").output
    assert "never asks for or stores your Wi-Fi passphrase" in policy


def test_dry_run_writes_nothing(cfgfile, tmp_path):
    r = run(cfgfile, "--dry-run", "monitor", "start", "--replay", str(FIXTURES / "deauth_burst.jsonl"))
    assert r.exit_code == 0 and "dry-run" in r.output and "POSSIBLE_DEAUTH_ATTACK" in r.output
    assert not (tmp_path / "var").exists()


def test_network_commands(cfgfile, tmp_path):
    r = run(cfgfile, "network", "add", "--name", "office", "--ssid", "OfficeNet", "--bssid", "aa-bb-cc-00-11-22",
            "--channel", "44", "--expect", "WPA3", "--pmf", "required")
    assert r.exit_code == 0 and "AA:BB:CC:00:11:22" in r.output
    assert (tmp_path / "networks.yaml").exists()
    listed = run(cfgfile, "network", "list").output
    assert "office" in listed and "registry" in listed and "home" in listed
    r = run(cfgfile, "network", "add", "--name", "home", "--ssid", "x")
    assert r.exit_code == 1 and "edit it there" in r.output
    r = run(cfgfile, "network", "add", "--name", "guest", "--ssid", "Guest")
    assert "unconfigured" in r.output and "no nearby AP is adopted" in r.output
    r = run(cfgfile, "--dry-run", "network", "remove", "office")
    assert "would remove" in r.output
    assert "office" in run(cfgfile, "network", "list").output
    assert run(cfgfile, "network", "remove", "office").exit_code == 0
    assert "office" not in run(cfgfile, "network", "list").output


def test_network_add_interactive(cfgfile):
    r = run(cfgfile, "network", "add", "-i", input="lab\nLabNet\n\n\nWPA3\n")
    assert r.exit_code == 0, r.output
    assert "name: lab" in r.output and "unconfigured" in r.output


def test_baseline_commands(cfgfile, tmp_path):
    r = run(cfgfile, "--dry-run", "baseline", "create", "--replay", str(FIXTURES / "normal.jsonl"))
    assert "Baseline: home" in r.output and "not saved" in r.output
    r = run(cfgfile, "baseline", "create", "--replay", str(FIXTURES / "normal.jsonl"))
    assert r.exit_code == 0 and "saved baseline(s): home" in r.output
    shown = run(cfgfile, "baseline", "show").output
    assert "RSSI" in shown and "WPA2/WPA3-TRANSITION" in shown
    r = run(cfgfile, "baseline", "create", "--from-db", "--since", "3000d")
    assert "saved baseline(s): home" in r.output


def test_kismet_config_and_check(cfgfile):
    out = run(cfgfile, "kismet", "config").output
    assert 'apspoof=home:ssid="ExampleSSID"' in out and "enable_logging=false" in out
    r = run(cfgfile, "kismet", "check")
    assert r.exit_code == 1 and "not reachable" in r.output


@pytest.fixture
def fake_host(tmp_path, monkeypatch):
    fs, route = host_sysfs(tmp_path)
    runners = []

    def runner_factory(dry_run=False, timeout=10.0):
        r = host_runner(dry_run=dry_run)
        runners.append(r)
        return r

    monkeypatch.setattr(cli, "CommandRunner", runner_factory)
    monkeypatch.setattr(cli, "InterfaceGuard", functools.partial(InterfaceGuard, sysfs_root=fs.net,
                                                                  route_file=route))

    class FakeDiscovery(discovery.Discovery):
        def __init__(self, runner=None, **kw):
            super().__init__(runner, sysfs_root=fs.net, route_file=route)

    monkeypatch.setattr(discovery, "Discovery", FakeDiscovery)
    return fs, runners


def test_sensor_prepare_prints_plan_without_apply(cfgfile, fake_host):
    fs, runners = fake_host
    r = run(cfgfile, "sensor", "prepare", "--channel", "36")
    assert r.exit_code == 0, r.output
    assert "iw dev wlx00c0cab85c32 set type monitor" in r.output and "Not executed" in r.output
    assert all(not r.executed for r in runners)
    r = run(cfgfile, "--dry-run", "sensor", "prepare", "--apply")
    assert "--dry-run" in r.output and all(not r.executed for r in runners)


def test_sensor_prepare_apply_touches_only_sensor(cfgfile, fake_host):
    fs, runners = fake_host
    r = run(cfgfile, "sensor", "prepare", "--apply", "--channel", "36")
    assert r.exit_code == 0, r.output
    executed = [argv for rr in runners for argv in rr.executed]
    assert executed and all("wlx00c0cab85c32" in argv and "wlo1" not in argv for argv in executed)
    assert "protected interfaces unchanged: wlo1" in r.output


def test_sensor_prepare_refuses_protected_phy(tmp_path, fake_host):
    fs, runners = fake_host
    fs.add_wireless("wlo1mon", phy="phy0", mac="02:00:00:00:00:01", driver="iwlwifi")
    path = tmp_path / "c2.yaml"
    path.write_text(yaml.safe_dump({"sensor": {"interface": "wlo1mon"}}))
    r = CliRunner().invoke(cli.main, ["-c", str(path), "sensor", "prepare", "--apply"])
    assert r.exit_code == 1 and "protected" in r.output
    assert all(not rr.executed for rr in runners)


def test_sensor_list_and_check(cfgfile, fake_host):
    out = run(cfgfile, "sensor", "list").output
    assert "wlx00c0cab85c32" in out and "mt7921u" in out and "protected (never modified)" in out
    r = run(cfgfile, "sensor", "check")
    assert "Driver    : mt7921u" in r.output and "Bands     : 2.4 / 5 / 6 GHz" in r.output
    assert "Monitor   : supported" in r.output and "Regdomain : KR" in r.output
    assert "protected-interfaces: unchanged (wlo1)" in r.output
    assert r.exit_code == 0
