import pytest
import yaml

from conftest import HOME_BSSID, HOME_BSSID_24G, ROGUE_BSSID, make_config
from daybreak.config import load_config
from daybreak.models import Event, Severity
from daybreak.pipeline import Pipeline
from daybreak.registry import RegistryError, add_network, remove_network
from test_correlation import of_type, run_fixture

T0 = 1790000000.0
TRANSITION = {"akms": ["PSK", "SAE"], "pmf": "capable"}
WPA3 = {"akms": ["SAE"], "pmf": "required"}
WPA2 = {"akms": ["PSK"], "pmf": "disabled"}


def beacon(t, bssid=HOME_BSSID, security=TRANSITION, channel=36, ssid="ExampleSSID", rssi=-40, **kw):
    return Event.from_dict({"ts": T0 + t, "type": kw.pop("type", "beacon"), "bssid": bssid, "src": bssid,
                            "ssid": ssid, "channel": channel, "rssi": rssi, "security": security, **kw})


def run(p, events):
    for e in events:
        p.process(e)
    return p.alerts


def types(alerts):
    return [a.alert_type for a in alerts]


def test_evil_twin_fixture(config):
    p, _ = run_fixture(config, "evil_twin.jsonl")
    twin = of_type(p.alerts, "POSSIBLE_EVIL_TWIN")
    assert twin, types(p.alerts)
    a = twin[-1]
    labels = [c.label for c in a.components]
    assert "unknown BSSID for protected SSID" in labels
    assert "security downgrade" in labels and "PMF capability missing" in labels
    assert "channel anomaly" in labels
    assert a.severity >= Severity.HIGH and a.bssid == ROGUE_BSSID and a.network == "home"
    assert a.details["rogue_bssids"] == [ROGUE_BSSID]
    unknown = of_type(p.alerts, "UNKNOWN_BSSID_FOR_PROTECTED_SSID")
    assert len(unknown) == 1 and unknown[0].severity is Severity.LOW  # warned, not judged


def test_unknown_bssid_with_same_security_is_only_a_warning(config):
    p = Pipeline(config)
    alerts = run(p, [beacon(0), beacon(1, bssid=ROGUE_BSSID, channel=36)])
    assert types(alerts) == ["UNKNOWN_BSSID_FOR_PROTECTED_SSID"]
    assert "add it to the bssids of 'home'" in alerts[0].details["hint"]


def test_continuous_beacons_report_once(config):
    p = Pipeline(config)
    events = [beacon(i) for i in range(0, 100, 5)] + [beacon(i, bssid=ROGUE_BSSID, security=WPA2, channel=11)
                                                      for i in range(1, 100, 5)]
    alerts = run(p, events)
    for kind in ("UNKNOWN_BSSID_FOR_PROTECTED_SSID", "SECURITY_DOWNGRADE", "PMF_DOWNGRADE", "CHANNEL_ANOMALY"):
        assert len(of_type(alerts, kind)) == 1, kind
    assert len(of_type(alerts, "POSSIBLE_EVIL_TWIN")) == 1


def test_wpa3_to_wpa2_downgrade_on_registered_bssid(tmp_path):
    cfg = make_config(tmp_path, protected_networks=[{
        "name": "home", "ssid": "ExampleSSID", "bssids": [HOME_BSSID], "channels": [36],
        "security": {"expected": ["WPA3"], "pmf": "required"}}])
    p = Pipeline(cfg)
    alerts = run(p, [beacon(0, security=WPA3), beacon(10, security=WPA2)])
    downs = of_type(alerts, "SECURITY_DOWNGRADE")
    assert downs and downs[0].details["authorized"] is True
    assert "WPA3-SAE" in str(downs) and "WPA2-PSK" in downs[0].summary
    assert of_type(alerts, "PMF_DOWNGRADE")
    assert not of_type(alerts, "POSSIBLE_EVIL_TWIN")  # a reconfiguration is possible: no twin claim


def test_pmf_disappearance_and_encryption_change(config):
    p = Pipeline(config)
    alerts = run(p, [beacon(0), beacon(5, security={"akms": ["PSK", "SAE"], "pmf": "disabled"})])
    pmf = of_type(alerts, "PMF_DOWNGRADE")
    assert len(pmf) == 1
    assert pmf[0].summary == ("PMF capability missing: PMF disabled advertised "
                              "(registry expects PMF capable; was PMF capable)")
    p2 = Pipeline(config)
    changed = run(p2, [beacon(0), beacon(5, security={"akms": ["PSK", "SAE", "FT-PSK"], "pmf": "capable"})])
    assert types(changed) == ["ENCRYPTION_CHANGE"]


def test_cloned_bssid_alternating_profiles(config):
    p = Pipeline(config)
    events = []
    for i in range(8):  # genuine AP and a clone with the same BSSID interleave
        events.append(beacon(i * 2, security=TRANSITION))
        events.append(beacon(i * 2 + 1, security=WPA2, rssi=-30))
    alerts = run(p, events)
    assert of_type(alerts, "POSSIBLE_EVIL_TWIN")
    conflict = [a for a in of_type(alerts, "SECURITY_DOWNGRADE") if a.details.get("bssid_conflict")]
    assert conflict and "possible cloned BSSID" in conflict[0].summary


def test_incompatible_open_duplicate(config):
    p = Pipeline(config)
    alerts = run(p, [beacon(0), beacon(1, bssid=ROGUE_BSSID, security={}, channel=6)])
    assert of_type(alerts, "INCOMPATIBLE_DUPLICATE_SSID")
    assert of_type(alerts, "POSSIBLE_EVIL_TWIN")[0].severity >= Severity.HIGH


def test_channel_anomaly_for_registered_ap(config):
    p = Pipeline(config)
    alerts = run(p, [beacon(0, channel=149)])
    assert types(alerts) == ["CHANNEL_ANOMALY"]


def test_kismet_and_ie_profiles_do_not_flap(config):
    p = Pipeline(config)
    ie = beacon(0)
    kismet = Event.from_dict({**beacon(1).to_dict(), "metadata": {"source_backend": "kismet"},
                              "security": {**TRANSITION, "source": "kismet"}})
    assert run(p, [ie, kismet, beacon(2)]) == []


def test_unconfigured_network_is_never_adopted(config):
    p = Pipeline(config)
    alerts = run(p, [beacon(0, bssid=ROGUE_BSSID, ssid="LabNet", security=WPA2)])
    assert alerts == []
    assert p.registry.by_name("lab").status == "unconfigured"
    assert p.registry.is_authorized("LabNet", ROGUE_BSSID) is None


def test_similar_bssid_hint(config):
    p = Pipeline(config)
    alerts = run(p, [beacon(0), beacon(1, bssid="AA:BB:CC:DD:EE:F1")])
    assert alerts[0].details["similar_to"] in (HOME_BSSID, HOME_BSSID_24G)


def test_kismet_apspoof_with_cryptodrop_makes_twin(config):
    p = Pipeline(config)
    common = {"type": "kismet_alert", "bssid": ROGUE_BSSID, "src": ROGUE_BSSID, "channel": 11}
    run(p, [Event.from_dict({**common, "ts": T0, "kismet_header": "APSPOOF",
                             "kismet_text": "Unauthorized device advertising SSID 'ExampleSSID'"}),
            Event.from_dict({**common, "ts": T0 + 1, "kismet_header": "CRYPTODROP",
                             "kismet_text": "SSID 'ExampleSSID' stopped advertising encryption"})])
    assert of_type(p.alerts, "POSSIBLE_EVIL_TWIN")


# -- registry ---------------------------------------------------------------------------------------

def test_registry_add_list_remove(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump({"protected_networks": [{"name": "home", "ssid": "ExampleSSID",
                                                                "bssids": [HOME_BSSID]}]}))
    cfg = load_config(cfg_path)
    net = add_network(cfg, name="office", ssid="OfficeNet", bssids=["aa-bb-cc-00-11-22"], channels=[44],
                      expected=["wpa3"], pmf="required")
    assert net.bssids == ["AA:BB:CC:00:11:22"] and net.security.expected == ["WPA3"]
    cfg = load_config(cfg_path)
    assert cfg.network("office").origin == "registry"
    with pytest.raises(RegistryError, match="already exists"):
        add_network(cfg, name="office", ssid="OfficeNet")
    with pytest.raises(RegistryError, match="config"):
        add_network(cfg, name="home", ssid="Other")
    with pytest.raises(RegistryError, match="invalid MAC"):
        add_network(cfg, name="bad", ssid="x", bssids=["nope"])
    add_network(cfg, name="office", ssid="OfficeNet", bssids=[], replace=True)
    assert load_config(cfg_path).network("office").status == "unconfigured"
    assert remove_network(load_config(cfg_path), "office")
    assert load_config(cfg_path).network("office") is None
    assert not remove_network(load_config(cfg_path), "office")


def test_registry_dry_run_writes_nothing(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text("{}\n")
    cfg = load_config(cfg_path)
    add_network(cfg, name="x", ssid="X", dry_run=True)
    assert not cfg.registry_path.exists()
