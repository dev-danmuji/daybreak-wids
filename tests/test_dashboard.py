import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from conftest import make_config  # noqa: E402
from daybreak.baseline.engine import build_from_events, save_baselines  # noqa: E402
from daybreak.dashboard.app import create_app, is_loopback, serve  # noqa: E402
from daybreak.runtime import build_runtime  # noqa: E402
from test_baseline import fixture_events  # noqa: E402
from test_correlation import run_fixture  # noqa: E402


@pytest.fixture
def client(tmp_path):
    cfg = make_config(tmp_path)
    return cfg, TestClient(create_app(cfg), base_url="http://127.0.0.1")


def test_empty_state(client):
    cfg, c = client
    r = c.get("/api/status")
    assert r.status_code == 200 and r.json()["threat_level"] == "NORMAL"
    assert r.json()["sensor"]["interface"] == "wlx00c0cab85c32"
    assert c.get("/api/alerts").json() == [] and c.get("/api/baseline").json() == []
    assert c.get("/api/timeline").json()["buckets"] == []
    nets = c.get("/api/networks").json()
    assert [n["network"] for n in nets] == ["home", "lab"]


def test_static_and_security_headers(client):
    _, c = client
    r = c.get("/")
    assert r.status_code == 200 and "DAYBREAK WIDS" in r.text
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert c.get("/static/app.js").status_code == 200
    assert c.get("/static/style.css").headers["content-type"].startswith("text/css")
    assert c.get("/static/..%2fapp.py").status_code == 404
    assert c.get("/static/index.py").status_code == 404


def test_read_only_and_host_check(client):
    _, c = client
    assert c.post("/api/alerts").status_code == 405
    assert c.delete("/api/alerts").status_code == 405
    evil = TestClient(c.app, base_url="http://attacker.example")
    assert evil.get("/api/status").status_code == 400  # DNS-rebinding protection


def test_data_after_replay(tmp_path):
    cfg = make_config(tmp_path)
    rt = build_runtime(cfg)
    p, _ = run_fixture(cfg, "handshake_pattern.jsonl", db=rt.db, sink=rt.alerts.submit)
    p.flush()
    ids = rt.db.sync_networks(cfg.protected_networks)
    save_baselines(rt.db, {k: v for k, v in build_from_events(cfg, fixture_events("normal.jsonl")).items()
                           if v["events"]}, ids)
    rt.close()
    c = TestClient(create_app(cfg), base_url="http://127.0.0.1")
    alerts = c.get("/api/alerts", params={"hours": 24 * 365}).json()
    assert any(a["alert_type"] == "POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT" for a in alerts)
    tl = c.get("/api/timeline", params={"minutes": 10}).json()
    assert tl["anchor"] and sum(b.get("deauth", 0) for b in tl["buckets"]) > 0  # anchored at recorded data
    assert any(a["severity"] in ("HIGH", "CRITICAL") for a in tl["alerts"])
    home = c.get("/api/networks").json()[0]
    assert home["mode"] == "WPA2/WPA3-TRANSITION" and home["pmf"] == "capable"
    base = c.get("/api/baseline").json()
    assert base[0]["network"] == "home" and base[0]["rates"]["disconnects"]["median"] == 0
    assert c.get("/api/alerts", params={"min_severity": "bogus"}).status_code == 400


def test_bind_policy(tmp_path):
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost")
    assert not is_loopback("0.0.0.0") and not is_loopback("192.168.0.10")
    with pytest.raises(ValueError, match="refusing"):
        serve(make_config(tmp_path), host="0.0.0.0", port=8765)
