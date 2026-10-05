import pytest

from conftest import HOME_BSSID, make_config
from daybreak.detectors.base import DetectionContext
from daybreak.detectors.deauth import DeauthDetector
from daybreak.detectors.window import SlidingWindow, Trigger
from daybreak.models import Event
from daybreak.registry import NetworkRegistry

T0 = 1790000000.0
STAS = [f"10:22:33:44:55:{i:02X}" for i in range(16)]


def ev(kind, t, dst=STAS[0], src=HOME_BSSID, bssid=HOME_BSSID, **kw):
    return Event.from_dict({"ts": T0 + t, "type": kind, "bssid": bssid, "src": src, "dst": dst,
                            "channel": kw.pop("channel", 36), **kw})


@pytest.fixture
def setup(tmp_path):
    cfg = make_config(tmp_path)
    ctx = DetectionContext(cfg, NetworkRegistry(cfg.protected_networks))
    return DeauthDetector(cfg.detection.deauth), ctx


def run(det, ctx, events):
    out = []
    for e in events:
        ctx.observe(e)
        out += det.process(e, ctx)
    return out


def types(findings):
    return [f.finding_type for f in findings]


# -- sliding window / trigger primitives ---------------------------------------------------------

def test_sliding_window_expiry_and_order():
    w = SlidingWindow(5.0)
    for t in (0, 1, 2, 3):
        w.add(t, t)
    assert w.count(4.9) == 4
    assert w.count(5.0) == 3          # t=0 is exactly window-old -> expired
    w.add(2.5, "late")                # out-of-order insert stays sorted
    assert w.values(6.0) == [2, "late", 3]
    assert w.distinct(100.0) == set()


def test_trigger_fire_escalate_rearm():
    t = Trigger(10, strict=True)
    assert t.update(10) is None       # threshold is "more than 10"
    assert t.update(11) == "fire"
    assert t.update(15) is None
    assert t.update(22) == "escalate"
    assert t.update(4) is None        # below 50% -> re-armed
    assert t.update(11) == "fire"


# -- burst threshold ---------------------------------------------------------------------------------

def test_single_deauth_is_not_an_attack(setup):
    det, ctx = setup
    assert run(det, ctx, [ev("deauth", 0, reason=3)]) == []


def test_burst_threshold_is_strictly_greater(setup):
    det, ctx = setup
    ten = [ev("deauth", i * 0.4) for i in range(10)]
    assert types(run(det, ctx, ten)) == []
    eleventh = run(det, ctx, [ev("deauth", 4.2)])
    assert types(eleventh) == ["DEAUTH_BURST"]
    f = eleventh[0]
    assert f.details["frames"] == 11 and f.points == 30 and f.network == "home"
    assert "11 frames/5s" in f.detail and STAS[0] in f.stations


def test_burst_requires_frames_within_window(setup):
    det, ctx = setup
    spread = [ev("deauth", i * 0.6) for i in range(20)]  # ~8.3 frames per 5s
    assert "DEAUTH_BURST" not in types(run(det, ctx, spread))


def test_burst_fires_once_then_escalates(setup):
    det, ctx = setup
    frames = [ev("deauth" if i % 2 else "disassoc", i * 0.1) for i in range(40)]
    found = [f for f in run(det, ctx, frames) if f.finding_type == "DEAUTH_BURST"]
    assert [f.details["frames"] for f in found] == [11, 22]
    assert found[1].details["escalation"] is True
    assert found[0].details["deauth"] + found[0].details["disassoc"] == 11


def test_bursts_are_per_bssid(tmp_path):
    cfg = make_config(tmp_path, detection={"scope": "all"})
    ctx = DetectionContext(cfg, NetworkRegistry(cfg.protected_networks, scope="all"))
    det = DeauthDetector(cfg.detection.deauth)
    other = "02:00:00:00:00:AA"
    mixed = [ev("deauth", i * 0.2, bssid=HOME_BSSID if i % 2 else other,
                src=HOME_BSSID if i % 2 else other) for i in range(20)]
    assert "DEAUTH_BURST" not in types(run(det, ctx, mixed))


# -- broadcast / multi-client ---------------------------------------------------------------------------

def test_repeated_broadcast_disconnect(setup):
    det, ctx = setup
    # stations seen associated before the broadcast deauth
    for i, sta in enumerate(STAS[:4]):
        ctx.observe(Event.from_dict({"ts": T0 - 30 + i, "type": "eapol", "bssid": HOME_BSSID,
                                     "src": sta, "dst": HOME_BSSID}))
    frames = [ev("deauth", t, dst="ff:ff:ff:ff:ff:ff") for t in (0, 20, 40)]
    found = run(det, ctx, frames)
    assert types(found) == ["BROADCAST_DEAUTH"]
    assert found[0].details["associated_stations"] == 4 and len(found[0].stations) == 4
    assert found[0].label == "broadcast disconnect"


def test_two_broadcasts_are_tolerated(setup):
    det, ctx = setup
    assert run(det, ctx, [ev("deauth", 0, dst="ff:ff:ff:ff:ff:ff"),
                          ev("disassoc", 30, dst="ff:ff:ff:ff:ff:ff")]) == []


def test_multi_client_disconnects(setup):
    det, ctx = setup
    found = run(det, ctx, [ev("deauth", i * 5, dst=STAS[i]) for i in range(3)])
    assert types(found) == ["MULTI_CLIENT_DEAUTH"]
    assert found[0].stations == frozenset(STAS[:3])


def test_client_initiated_disconnect_counts_station(setup):
    det, ctx = setup
    frames = [ev("disassoc", i * 5, src=STAS[i], dst=HOME_BSSID, reason=8) for i in range(3)]
    found = run(det, ctx, frames)
    assert types(found) == ["MULTI_CLIENT_DEAUTH"]


# -- suspicious source -------------------------------------------------------------------------------

def _beacons(ctx, rssi=-40, n=12, pmf="capable"):
    for i in range(n):
        ctx.observe(Event.from_dict({"ts": T0 - 100 + i, "type": "beacon", "bssid": HOME_BSSID,
                                     "src": HOME_BSSID, "ssid": "ExampleSSID", "channel": 36,
                                     "rssi": rssi + (i % 3) - 1,
                                     "security": {"akms": ["PSK", "SAE"], "pmf": pmf}}))


def test_rssi_deviation_marks_suspicious_source(setup):
    det, ctx = setup
    _beacons(ctx)
    found = run(det, ctx, [ev("deauth", i, rssi=-85, dst=STAS[i]) for i in range(3)])
    sus = [f for f in found if f.finding_type == "SUSPICIOUS_SOURCE"]
    assert len(sus) == 1 and "RSSI -85 dBm vs AP -40" in sus[0].detail


def test_normal_rssi_is_not_suspicious(setup):
    det, ctx = setup
    _beacons(ctx)
    found = run(det, ctx, [ev("deauth", i * 20, rssi=-43, dst=STAS[0]) for i in range(5)])
    assert "SUSPICIOUS_SOURCE" not in types(found)


def test_unprotected_deauth_on_pmf_required_network(setup):
    det, ctx = setup
    _beacons(ctx, pmf="required")
    frames = [ev("deauth", i * 2, protected=False, dst=STAS[0]) for i in range(3)]
    sus = [f for f in run(det, ctx, frames) if f.finding_type == "SUSPICIOUS_SOURCE"]
    assert sus and "requires PMF" in sus[0].detail
    det2, ctx2 = DeauthDetector(ctx.config.detection.deauth), DetectionContext(ctx.config, ctx.registry)
    _beacons(ctx2, pmf="required")
    protected = [ev("deauth", i * 2, protected=True, dst=STAS[0]) for i in range(3)]
    assert "SUSPICIOUS_SOURCE" not in types(run(det2, ctx2, protected))


def test_channel_mismatch_on_5ghz(setup):
    det, ctx = setup
    frames = [ev("deauth", i * 2, channel=149, dst=STAS[0]) for i in range(3)]
    sus = [f for f in run(det, ctx, frames) if f.finding_type == "SUSPICIOUS_SOURCE"]
    assert sus and "channel 149" in sus[0].detail
    det2 = DeauthDetector(ctx.config.detection.deauth)
    near = [ev("deauth", i * 2, channel=7, dst=STAS[0]) for i in range(3)]  # 2.4 GHz leakage near ch 6
    assert "SUSPICIOUS_SOURCE" not in types(run(det2, ctx, near))


def test_invalid_reason_code(setup):
    det, ctx = setup
    found = run(det, ctx, [ev("deauth", 0, reason=200)])
    assert types(found) == ["INVALID_REASON_CODE"] and found[0].points == 5
    assert run(det, ctx, [ev("deauth", 1, reason=200)]) == []  # no repeat within the minute


def test_non_disconnect_events_ignored(setup):
    det, ctx = setup
    assert run(det, ctx, [Event.from_dict({"ts": T0, "type": "eapol", "bssid": HOME_BSSID})]) == []
