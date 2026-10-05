import json

from conftest import FIXTURES, HOME_BSSID, ROGUE_BSSID, make_config
from daybreak.baseline.engine import (
    BaselineBuilder, BaselineStore, build_from_events, describe_rates, deviation, save_baselines,
)
from daybreak.models import Alert, Event, ScoreComponent, Severity
from daybreak.pipeline import Pipeline
from daybreak.scoring import explain, threat_level
from daybreak.sensor.replay import ReplayBackend
from daybreak.storage import Database
from test_correlation import of_type

T0 = 1790000000.0
STAS = [f"10:22:33:44:55:{i:02X}" for i in range(1, 9)]


def fixture_events(name):
    b = ReplayBackend(FIXTURES / name)
    b.open()
    out = []
    while not b.finished:
        out += b.poll(0)
    b.close()
    return out


def learn(config, name="normal.jsonl"):
    return build_from_events(config, fixture_events(name))


def test_describe_rates_is_robust():
    r = describe_rates([0, 0, 0, 0, 0, 1, 0, 0, 0, 40])
    assert r["median"] == 0 and r["mad"] == 0 and r["max"] == 40 and r["mean"] == 4.1
    assert describe_rates([]) == {"mean": 0.0, "std": 0.0, "median": 0.0, "mad": 0.0, "p95": 0.0, "max": 0.0}


def test_baseline_contents_from_normal_fixture(config):
    docs = learn(config)
    home = docs["home"]
    assert home["duration"] > 800 and home["buckets"] >= 15
    assert set(home["known_bssids"]) == {"AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:F0"}
    assert home["known_channels"] == [6, 36]
    assert home["security"]["mode"] == "WPA2/WPA3-TRANSITION"
    rssi = home["bssids"][HOME_BSSID]["rssi"]
    assert -44 < rssi["mean"] < -38 and rssi["n"] >= 80
    rates = home["rates"]
    assert rates["disconnects"]["median"] == 0 and rates["disconnects"]["max"] >= 1
    assert rates["eapol"]["max"] >= 16
    assert home["clients"]["max"] == 4 and home["clients"]["min"] >= 1
    assert docs["lab"]["events"] == 0
    json.dumps(docs)  # serialisable


def test_baseline_ignores_unregistered_bssids(config):
    builder = BaselineBuilder(config)
    builder.add(Event.from_dict({"ts": T0, "type": "beacon", "bssid": ROGUE_BSSID, "ssid": "ExampleSSID",
                                 "channel": 11, "rssi": -30, "security": {"akms": ["PSK"]}}))
    builder.add(Event.from_dict({"ts": T0 + 1, "type": "beacon", "bssid": HOME_BSSID, "ssid": "ExampleSSID",
                                 "channel": 36, "rssi": -40, "security": {"akms": ["SAE"], "pmf": "required"}}))
    doc = builder.metrics()["home"]
    assert doc["known_bssids"] == [HOME_BSSID] and doc["candidate_bssids"] == [ROGUE_BSSID]
    assert doc["security"]["mode"] == "WPA3-SAE"


def test_baseline_saved_and_loaded(tmp_path, config):
    db = Database(tmp_path / "b.db")
    ids = db.sync_networks(config.protected_networks)
    docs = learn(config)
    saved = save_baselines(db, docs, ids)
    assert set(saved) == {"home", "lab"}
    store = BaselineStore.from_db(db)
    assert store.rate("home", "disconnects")["median"] == 0
    assert store.security_for("home", None).mode == "WPA2/WPA3-TRANSITION"
    assert store.rssi_for(HOME_BSSID)[2] >= 80
    assert store.channels_for(HOME_BSSID) == {36}
    # a second baseline replaces the first as active
    save_baselines(db, docs, ids)
    assert len(db.active_baselines()) == 2 and len(db.list_baselines()) == 4


def test_deviation_math(config):
    rate = {"median": 0.0, "mad": 0.0, "max": 3.0}
    z, sigma = deviation(10, rate, config.detection.baseline)
    assert sigma == 0.5 and z == 20.0


def _disconnect_minute(start, n, src=HOME_BSSID, dst=None):
    return [Event.from_dict({"ts": T0 + start + i * (55.0 / n), "type": "deauth", "bssid": HOME_BSSID,
                             "src": src, "dst": dst or STAS[i % 2], "reason": 3}) for i in range(n)]


def test_baseline_deviation_detected_below_fixed_thresholds(config):
    """8 disconnects/min never trips the fixed >10/5s burst rule, but is far above normal."""
    store = BaselineStore(learn(config))
    p = Pipeline(config, baseline=store)
    for e in _disconnect_minute(0, 8):
        p.process(e)
    dev = of_type(p.alerts, "BASELINE_DEVIATION")
    assert dev and dev[0].details["metric"] == "disconnects" and dev[0].details["value"] >= 5
    assert "vs normal median 0" in dev[0].summary
    assert not of_type(p.alerts, "DEAUTH_BURST")


def test_no_deviation_without_baseline_or_within_normal(config):
    p = Pipeline(config)
    for e in _disconnect_minute(0, 8):
        p.process(e)
    assert not of_type(p.alerts, "BASELINE_DEVIATION")
    store = BaselineStore(learn(config))
    p2 = Pipeline(config, baseline=store)
    for e in _disconnect_minute(0, 1):
        p2.process(e)
    assert not of_type(p2.alerts, "BASELINE_DEVIATION")


def test_baseline_deviation_joins_deauth_score(config):
    store = BaselineStore(learn(config))
    p = Pipeline(config, baseline=store)
    for i in range(30):
        p.process(Event.from_dict({"ts": T0 + i * 0.15, "type": "deauth", "bssid": HOME_BSSID,
                                   "src": HOME_BSSID, "dst": STAS[i % 4], "reason": 7}))
    attack = of_type(p.alerts, "POSSIBLE_DEAUTH_ATTACK")[-1]
    assert "baseline deviation" in [c.label for c in attack.components]


def test_baseline_rssi_used_for_suspicious_source(config):
    store = BaselineStore(learn(config))
    p = Pipeline(config, baseline=store)  # no live beacons yet: falls back to the baseline RSSI
    for i in range(3):
        p.process(Event.from_dict({"ts": T0 + i, "type": "deauth", "bssid": HOME_BSSID, "src": HOME_BSSID,
                                   "dst": STAS[i], "rssi": -85, "reason": 7}))
    sus = of_type(p.alerts, "SUSPICIOUS_SOURCE")
    assert sus and "RSSI -85 dBm vs AP -4" in sus[0].summary


def test_baseline_security_reference_for_downgrade(tmp_path):
    cfg = make_config(tmp_path, protected_networks=[{"name": "home", "ssid": "ExampleSSID",
                                                     "bssids": [HOME_BSSID]}])  # no expectations
    store = BaselineStore({"home": {"bssids": {HOME_BSSID: {"security": {"akms": ["SAE"], "pmf": "required"},
                                                            "channels": [36]}},
                                    "security": {"akms": ["SAE"], "pmf": "required"}, "rates": {}}})
    p = Pipeline(cfg, baseline=store)
    p.process(Event.from_dict({"ts": T0, "type": "beacon", "bssid": HOME_BSSID, "src": HOME_BSSID,
                               "ssid": "ExampleSSID", "channel": 40, "security": {"akms": ["PSK"]}}))
    kinds = {a.alert_type for a in p.alerts}
    assert {"SECURITY_DOWNGRADE", "PMF_DOWNGRADE", "CHANNEL_ANOMALY"} <= kinds


def test_threat_level_and_explain():
    a = Alert("X", T0, 82, [ScoreComponent(30, "deauth burst"), ScoreComponent(20, "broadcast disconnect"),
                            ScoreComponent(15, "multiple stations affected"),
                            ScoreComponent(17, "EAPOL reauthentication surge")])
    assert explain(a.score, a.components) == [
        "Risk 82 HIGH", "+30 deauth burst", "+20 broadcast disconnect", "+15 multiple stations affected",
        "+17 EAPOL reauthentication surge"]
    assert threat_level([]) == "NORMAL"
    assert threat_level([{"severity": "INFO"}]) == "NORMAL"
    assert threat_level([{"severity": "MEDIUM"}]) == "ELEVATED"
    assert threat_level([a]) == "HIGH"
    assert threat_level([{"severity": "CRITICAL"}, a]) == "CRITICAL"
    assert Severity.from_score(82) is Severity.HIGH
