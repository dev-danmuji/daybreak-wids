import pytest

from conftest import FIXTURES, HOME_BSSID, make_config
from daybreak.detectors.base import DetectionContext
from daybreak.detectors.eapol import EapolDetector
from daybreak.models import Event, Severity
from daybreak.pipeline import Deduplicator, Pipeline
from daybreak.registry import NetworkRegistry
from daybreak.sensor.replay import ReplayBackend

T0 = 1790000000.0
STAS = [f"10:22:33:44:55:{i:02X}" for i in range(1, 9)]


def run_fixture(config, name, **kw):
    backend = ReplayBackend(FIXTURES / name)
    backend.open()
    p = Pipeline(config, **kw)
    while not backend.finished:
        for ev in backend.poll(0):
            p.process(ev)
    backend.close()
    return p, backend


def of_type(alerts, t):
    return [a for a in alerts if a.alert_type == t]


# -- EAPOL detector ---------------------------------------------------------------------------------

def eapol(t, sta, msg, bssid=HOME_BSSID):
    src, dst = (bssid, sta) if msg in (1, 3) else (sta, bssid)
    return Event.from_dict({"ts": T0 + t, "type": "eapol", "bssid": bssid, "src": src, "dst": dst,
                            "eapol_type": "key", "eapol_msg": msg, "channel": 36})


def handshake(t, sta):
    return [eapol(t + i * 0.01, sta, m) for i, m in enumerate((1, 2, 3, 4))]


@pytest.fixture
def eapol_setup(tmp_path):
    cfg = make_config(tmp_path)
    return EapolDetector(cfg.detection.eapol), DetectionContext(cfg, NetworkRegistry(cfg.protected_networks))


def feed(det, ctx, events):
    out = []
    for e in events:
        out += det.process(e, ctx)
    return out


def test_normal_reconnects_do_not_trigger(eapol_setup):
    det, ctx = eapol_setup
    events = handshake(0, STAS[0]) + handshake(30, STAS[0]) + handshake(0, STAS[1])
    assert feed(det, ctx, events) == []


def test_station_reauth_surge(eapol_setup):
    det, ctx = eapol_setup
    events = handshake(0, STAS[0]) + handshake(15, STAS[0]) + handshake(30, STAS[0])
    found = feed(det, ctx, events)
    assert [f.details["scope"] for f in found] == ["station"]
    assert found[0].finding_type == "EAPOL_REAUTH_SURGE" and found[0].details["handshakes"] == 3
    assert found[0].points == 17 and found[0].stations == {STAS[0]}


def test_m1_retransmissions_are_one_attempt(eapol_setup):
    det, ctx = eapol_setup
    events = [eapol(t, STAS[0], 1) for t in (0, 1.0, 2.0, 2.5)]  # AP retrying message 1
    assert feed(det, ctx, events) == []


def test_bssid_level_surge(eapol_setup):
    det, ctx = eapol_setup
    events = [e for i, sta in enumerate(STAS[:4]) for e in handshake(i * 2, sta)]
    found = feed(det, ctx, events)
    assert [f.details["scope"] for f in found] == ["bssid"]
    assert found[0].details["stations"] == 4


def test_frame_count_fallback_without_message_numbers(eapol_setup):
    det, ctx = eapol_setup
    events = [Event.from_dict({"ts": T0 + i, "type": "eapol", "bssid": HOME_BSSID, "src": STAS[0],
                               "dst": HOME_BSSID}) for i in range(12)]
    found = feed(det, ctx, events)
    assert found and found[0].details["eapol_frames"] == 12


# -- dedup ---------------------------------------------------------------------------------------------

def test_duplicate_event_suppression():
    d = Deduplicator()
    a = Event.from_dict({"ts": T0, "type": "deauth", "bssid": HOME_BSSID, "src": HOME_BSSID,
                         "dst": STAS[0], "reason": 7, "seq": 5})
    same = Event.from_dict(a.to_dict())
    retry = Event.from_dict({**a.to_dict(), "timestamp": T0 + 0.002, "metadata": {"seq": 5, "retry": True}})
    later = Event.from_dict({**a.to_dict(), "timestamp": T0 + 1.0, "metadata": {"seq": 6}})
    assert not d.is_duplicate(a)
    assert d.is_duplicate(same)          # exact duplicate (e.g. backend re-delivery)
    assert d.is_duplicate(retry)         # 802.11 retransmission of the same frame
    assert not d.is_duplicate(later)
    no_retry_flag = Event.from_dict({**a.to_dict(), "timestamp": T0 + 0.003, "metadata": {"seq": 5}})
    assert not d.is_duplicate(no_retry_flag)  # identical seq without retry bit still counts


# -- risk scoring + correlation -----------------------------------------------------------------------

def test_normal_fixture_has_no_high_alert(config):
    p, backend = run_fixture(config, "normal.jsonl")
    assert backend.stats["malformed"] == 0 and p.stats["processed"] > 250
    assert not [a for a in p.alerts if a.severity >= Severity.HIGH]
    assert not of_type(p.alerts, "DEAUTH_BURST")
    assert not of_type(p.alerts, "POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT")


def test_deauth_burst_fixture(config):
    p, _ = run_fixture(config, "deauth_burst.jsonl")
    bursts = of_type(p.alerts, "DEAUTH_BURST")
    assert bursts and bursts[0].details["frames"] == 11
    attack = of_type(p.alerts, "POSSIBLE_DEAUTH_ATTACK")
    assert attack, [a.alert_type for a in p.alerts]
    final = attack[-1]
    labels = [c.label for c in final.components]
    assert "deauth burst" in labels and "multiple stations affected" in labels
    assert "suspicious source" in labels      # RSSI far from the AP's beacons
    assert final.severity >= Severity.MEDIUM
    assert final.score == sum(c.points for c in final.components)
    assert not of_type(p.alerts, "POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT")  # no reconnects in this fixture


def test_handshake_pattern_fixture(config):
    p, _ = run_fixture(config, "handshake_pattern.jsonl")
    hs = of_type(p.alerts, "POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT")
    assert hs, [a.alert_type for a in p.alerts]
    a = hs[0]
    labels = [c.label for c in a.components]
    assert labels[0] == "deauth burst"
    assert "disconnected stations re-authenticated" in labels
    assert a.severity >= Severity.HIGH
    assert a.details["affected_stations"] == 4 and a.details["reauthenticated_stations"] >= 1
    assert "not determined" in a.summary  # never claims success
    assert a.score_lines()[0].startswith("+30 deauth burst")
    # the EAPOL surge after the burst is reported as its own finding as well
    burst_ts = of_type(p.alerts, "DEAUTH_BURST")[0].timestamp
    assert [e for e in of_type(p.alerts, "EAPOL_REAUTH_SURGE") if e.timestamp > burst_ts]


def test_handshake_composite_escalates_with_eapol_surge(config):
    p = Pipeline(config)
    for i in range(12):  # plain burst: no broadcast, normal RSSI
        p.process(Event.from_dict({"ts": T0 + 0.2 * i, "type": "deauth", "bssid": HOME_BSSID,
                                   "src": HOME_BSSID, "dst": STAS[i % 4], "reason": 7, "channel": 36}))
    for i, sta in enumerate(STAS[:4]):
        for e in handshake(4 + i, sta):
            p.process(e)
    hs = of_type(p.alerts, "POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT")
    assert len(hs) == 2
    first, second = hs
    assert [c.label for c in first.components] == [
        "deauth burst", "multiple stations affected", "disconnected stations re-authenticated"]
    assert of_type(p.alerts, "POSSIBLE_DEAUTH_ATTACK")[0].score == 45
    assert first.score == 55 and first.severity is Severity.MEDIUM
    assert "EAPOL reauthentication surge" in [c.label for c in second.components]
    assert second.score == 72 and second.severity is Severity.HIGH
    assert second.score_lines() == [
        "+30 deauth burst (11 frames/5s, threshold >10)",
        "+15 multiple stations affected (3 stations in 30s)",
        "+17 EAPOL reauthentication surge (4 stations re-authenticating, 13 EAPOL frames in 60s)",
        "+10 disconnected stations re-authenticated (4 station(s), EAPOL 2.4s after disconnect)",
    ]


def test_eapol_before_disconnects_is_not_correlated(config):
    p = Pipeline(config)
    for i, sta in enumerate(STAS[:4]):          # normal start-up: everyone connects
        for e in handshake(i, sta):
            p.process(e)
    for i in range(12):                          # a later burst with no reconnects
        p.process(Event.from_dict({"ts": T0 + 50 + 0.2 * i, "type": "deauth", "bssid": HOME_BSSID,
                                   "src": HOME_BSSID, "dst": STAS[i % 4], "reason": 7}))
    assert not of_type(p.alerts, "POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT")


def test_score_is_explained_and_capped(config):
    p, _ = run_fixture(config, "handshake_pattern.jsonl")
    for a in p.alerts:
        assert a.components, a.alert_type
        assert 0 <= a.score <= 100
        assert a.score == min(100, sum(c.points for c in a.components))


def test_kismet_alert_and_own_detection_count_once(config):
    p = Pipeline(config)
    p.process(Event.from_dict({"ts": T0, "type": "kismet_alert", "bssid": HOME_BSSID, "src": HOME_BSSID,
                               "dst": "FF:FF:FF:FF:FF:FF", "kismet_header": "DEAUTHFLOOD",
                               "kismet_text": "deauth flood"}))
    for i in range(12):
        p.process(Event.from_dict({"ts": T0 + 0.1 * i, "type": "deauth", "bssid": HOME_BSSID,
                                   "src": HOME_BSSID, "dst": STAS[i % 4], "reason": 7}))
    attack = of_type(p.alerts, "POSSIBLE_DEAUTH_ATTACK")[-1]
    burst_lines = [c for c in attack.components if c.category == "deauth_burst" and c.label != "burst intensity"]
    assert len(burst_lines) == 1 and attack.score == 45  # not 30 + 30
    incident = p.correlator.incidents[f"bssid:{HOME_BSSID}"]
    assert incident.sources["deauth_burst"] == {"KISMET_DEAUTHFLOOD", "DEAUTH_BURST"}


def test_reconnect_without_burst_is_normal(config):
    p = Pipeline(config)
    p.process(Event.from_dict({"ts": T0, "type": "disassoc", "bssid": HOME_BSSID, "src": STAS[0],
                               "dst": HOME_BSSID, "reason": 8}))
    for e in handshake(1, STAS[0]):
        p.process(e)
    assert p.alerts == []


def test_out_of_scope_bssids_are_ignored(config):
    p = Pipeline(config)
    neighbour = "02:99:99:99:99:99"
    for i in range(30):
        p.process(Event.from_dict({"ts": T0 + 0.1 * i, "type": "deauth", "bssid": neighbour,
                                   "src": neighbour, "dst": STAS[0]}))
    assert p.alerts == [] and p.stats["out_of_scope"] == 30


def test_malformed_events_are_skipped(config):
    p, backend = run_fixture(config, "malformed.jsonl")
    assert backend.stats["malformed"] == 6
    assert backend.stats["events"] == 4
    assert p.stats["duplicates"] == 1 and p.stats["processed"] == 3


def test_sensor_flap_fixture(config):
    p, _ = run_fixture(config, "sensor_flap.jsonl")
    kinds = [a.alert_type for a in p.alerts]
    assert kinds == ["SENSOR_LOST", "SENSOR_RECOVERED"]
    assert p.alerts[0].severity is Severity.MEDIUM and p.alerts[1].severity is Severity.INFO
