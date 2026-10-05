from pathlib import Path

import pytest
import yaml

from daybreak.config import (
    ConfigError, ProtectedNetwork, config_from_dict, load_config, load_registry_file,
    save_registry_file,
)
from daybreak.safety import SafetyViolation

ROOT = Path(__file__).resolve().parents[1]


def test_example_config_loads():
    cfg = load_config(ROOT / "config.example.yaml")
    assert cfg.sensor.interface == "wlx00c0cab85c32"
    assert cfg.sensor.protected_interfaces == ["wlo1"]
    assert cfg.safety.passive_only and not cfg.safety.packet_injection
    assert not cfg.safety.transmit_management_frames
    home = cfg.network("home")
    assert home.bssids == ["AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:F0"] and home.status == "configured"
    assert home.channels == [36, 6]
    assert home.security.expected == ["WPA2", "WPA3"]
    assert cfg.database_path == ROOT / "var" / "daybreak.db"


def test_defaults_without_file(tmp_path):
    cfg = config_from_dict({}, base_dir=tmp_path)
    assert cfg.sensor.interface == "wlx00c0cab85c32"
    assert "wlo1" in cfg.sensor.protected_interfaces
    assert cfg.detection.deauth.burst_threshold == 10
    assert cfg.detection.deauth.burst_window == 5.0
    assert cfg.dashboard.host == "127.0.0.1"


@pytest.mark.parametrize("safety", [
    {"passive_only": False},
    {"packet_injection": True},
    {"transmit_management_frames": True},
])
def test_non_passive_safety_is_refused(tmp_path, safety):
    with pytest.raises(SafetyViolation):
        config_from_dict({"safety": safety}, base_dir=tmp_path)


def test_unknown_option_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="unknown option: detection.deauth.burst_treshold"):
        config_from_dict({"detection": {"deauth": {"burst_treshold": 3}}}, base_dir=tmp_path)


def test_type_errors(tmp_path):
    with pytest.raises(ConfigError, match="expected an integer"):
        config_from_dict({"detection": {"deauth": {"burst_threshold": "ten"}}}, base_dir=tmp_path)
    with pytest.raises(ConfigError, match="must be positive"):
        config_from_dict({"detection": {"deauth": {"burst_window": 0}}}, base_dir=tmp_path)


def test_sensor_cannot_be_protected_interface(tmp_path):
    with pytest.raises(ConfigError, match="dedicated adapter"):
        config_from_dict({"sensor": {"interface": "wlo1"}}, base_dir=tmp_path)


def test_dashboard_must_be_loopback(tmp_path):
    with pytest.raises(ConfigError, match="loopback"):
        config_from_dict({"dashboard": {"host": "0.0.0.0"}}, base_dir=tmp_path)
    cfg = config_from_dict({"dashboard": {"host": "0.0.0.0", "allow_remote": True}}, base_dir=tmp_path)
    assert cfg.dashboard.host == "0.0.0.0"


def test_network_without_bssid_is_unconfigured(tmp_path):
    cfg = config_from_dict({"protected_networks": [{"name": "lab", "ssid": "LabNet"}]},
                           base_dir=tmp_path)
    assert cfg.network("lab").status == "unconfigured"
    assert cfg.network("lab").bssids == []


@pytest.mark.parametrize("net,msg", [
    ({"name": "x"}, "'name' and 'ssid' are required"),
    ({"name": "x", "ssid": "s", "bssids": ["zz"]}, "invalid MAC"),
    ({"name": "x", "ssid": "s", "channels": [0]}, "invalid channel"),
    ({"name": "x", "ssid": "s", "security": {"expected": ["WPA4"]}}, "unknown protocol"),
    ({"name": "x", "ssid": "s", "security": {"pmf": "maybe"}}, "pmf must be"),
    ({"name": "x", "ssid": "s" * 40}, "longer than 32"),
])
def test_invalid_networks(tmp_path, net, msg):
    with pytest.raises(ConfigError, match=msg):
        config_from_dict({"protected_networks": [net]}, base_dir=tmp_path)


def test_duplicate_network_names(tmp_path):
    nets = [{"name": "a", "ssid": "x"}, {"name": "a", "ssid": "y"}]
    with pytest.raises(ConfigError, match="duplicate"):
        config_from_dict({"protected_networks": nets}, base_dir=tmp_path)


def test_bssids_are_normalized_and_deduplicated(tmp_path):
    cfg = config_from_dict({"protected_networks": [
        {"name": "a", "ssid": "x", "bssids": ["aa-bb-cc-dd-ee-ff", "AA:BB:CC:DD:EE:FF"]}]},
        base_dir=tmp_path)
    assert cfg.network("a").bssids == ["AA:BB:CC:DD:EE:FF"]


def test_registry_roundtrip(tmp_path):
    path = tmp_path / "networks.yaml"
    net = ProtectedNetwork(name="office", ssid="Office", bssids=["10:22:33:44:55:66"],
                           channels=[1], origin="registry")
    save_registry_file(path, [net])
    loaded = load_registry_file(path)
    assert loaded[0].name == "office" and loaded[0].origin == "registry"
    cfg = config_from_dict({}, base_dir=tmp_path)
    assert cfg.network("office").bssids == ["10:22:33:44:55:66"]
    assert yaml.safe_load(path.read_text())["protected_networks"][0]["ssid"] == "Office"


def test_unknown_weight_rejected(tmp_path):
    with pytest.raises(ConfigError, match="unknown scoring weight"):
        config_from_dict({"scoring": {"weights": {"deauth_brust": 10}}}, base_dir=tmp_path)


def test_kismet_url_must_not_carry_credentials(tmp_path):
    for url in ("http://admin:secret@127.0.0.1:2501", "http://admin@127.0.0.1:2501"):
        with pytest.raises(ConfigError, match="must not contain credentials"):
            config_from_dict({"backend": {"kismet": {"url": url}}}, base_dir=tmp_path)


def test_retention_and_dashboard_host_validation(tmp_path):
    with pytest.raises(ConfigError, match="retention_days"):
        config_from_dict({"storage": {"retention_days": -1}}, base_dir=tmp_path)
    assert config_from_dict({"storage": {"retention_days": 0}}, base_dir=tmp_path).storage.retention_days == 0
    for host in ("::1", "[::1]", "127.0.0.2", "localhost"):
        assert config_from_dict({"dashboard": {"host": host}}, base_dir=tmp_path).dashboard.host == host
    with pytest.raises(ConfigError, match="loopback"):
        config_from_dict({"dashboard": {"host": "0.0.0.0"}}, base_dir=tmp_path)
    with pytest.raises(ConfigError, match="allowed_hosts"):
        config_from_dict({"dashboard": {"host": "0.0.0.0", "allow_remote": True,
                                        "allowed_hosts": ["wids lan"]}}, base_dir=tmp_path)
