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


def _replayed(tmp_path, fixture="handshake_pattern.jsonl", **overrides):
    cfg = make_config(tmp_path, **overrides)
    rt = build_runtime(cfg)
    p, _ = run_fixture(cfg, fixture, db=rt.db, sink=rt.alerts.submit)
    p.flush()
    rt.close()
    return cfg


def test_security_headers_on_error_responses(client, monkeypatch):
    import daybreak.dashboard.app as dash

    _, c = client
    r = c.post("/api/status")
    assert r.status_code == 405 and r.headers["allow"] == "GET"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["cache-control"] == "no-store"
    rejected = TestClient(c.app, base_url="http://attacker.example").get("/")
    assert rejected.status_code == 400 and rejected.headers["x-frame-options"] == "DENY"
    monkeypatch.setattr(dash, "read_status", lambda path: 1 / 0)
    r = c.get("/api/status")
    assert r.status_code == 500 and r.json() == {"detail": "internal error"}
    assert "default-src 'self'" in r.headers["content-security-policy"]


def test_host_allow_list_stays_on_with_allow_remote(tmp_path):
    cfg = make_config(tmp_path, dashboard={"host": "0.0.0.0", "allow_remote": True, "allowed_hosts": ["wids.lan"]})
    app = create_app(cfg, allow_remote=True, bind_host="0.0.0.0")
    assert TestClient(app, base_url="http://wids.lan:8765").get("/api/status").status_code == 200
    assert TestClient(app, base_url="http://127.0.0.1").get("/api/status").status_code == 200
    assert TestClient(app, base_url="http://attacker.example").get("/api/status").status_code == 400
    alias = create_app(make_config(tmp_path), bind_host="127.0.0.2")
    assert TestClient(alias, base_url="http://127.0.0.2:8765").get("/api/status").status_code == 200
    open_cfg = make_config(tmp_path, dashboard={"host": "127.0.0.1", "allow_remote": True})
    with pytest.raises(ValueError, match="allowed_hosts"):
        serve(open_cfg, host="0.0.0.0", port=8765, allow_remote=True)  # refused before binding


def test_api_views_do_not_expose_internals(tmp_path):
    import json

    from daybreak.monitor import status_path

    cfg = _replayed(tmp_path)
    status_path(cfg).write_text(json.dumps({
        "state": "stopped", "pid": 424242, "updated": 1.0, "config": "/home/someone/config.yaml",
        "backend": {"name": "kismet", "healthy": False, "detail": "d", "extra": {"source": "x"}},
        "backend_error": "Kismet not reachable at http://127.0.0.1:2501"}))
    c = TestClient(create_app(cfg), base_url="http://127.0.0.1")
    body = c.get("/api/status").text
    for leaked in ("424242", "/home/someone", "backend_error", "not reachable", "extra"):
        assert leaked not in body
    assert c.get("/api/status").json()["monitor"]["backend"] == {"name": "kismet", "healthy": False}
    alerts = c.get("/api/alerts", params={"hours": 24 * 365}).json()
    assert alerts and all(set(a["reason"]) == {"components"} for a in alerts)
    assert all("summary" not in a for a in alerts)  # unused by the UI; may name a station


def test_alerts_of_a_recorded_period(tmp_path):
    cfg = _replayed(tmp_path)
    c = TestClient(create_app(cfg), base_url="http://127.0.0.1")
    tl = c.get("/api/timeline", params={"minutes": 60}).json()
    recorded = c.get("/api/alerts", params={"hours": 24, "until": tl["anchor"]}).json()
    assert any(a["alert_type"] == "POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT" for a in recorded)
    assert c.get("/api/alerts", params={"hours": 1, "until": tl["start"] - 7200}).json() == []
    assert c.get("/api/alerts", params={"until": -1}).status_code == 422


def test_unknown_bssids_are_counted_not_listed_without_bound(tmp_path):
    cfg = make_config(tmp_path)
    rt = build_runtime(cfg)
    for i in range(80):  # beacon flood: random BSSIDs advertising the protected SSID
        rt.db.upsert_ap(bssid=f"02:00:00:00:{i // 256:02X}:{i % 256:02X}", ssid="ExampleSSID", network_id=None,
                        authorized=False, channel=36, security=None, phy=None, rssi=-60, timestamp=1790000000.0 + i)
    rt.close()
    home = TestClient(create_app(cfg), base_url="http://127.0.0.1").get("/api/networks").json()[0]
    assert home["unknown_bssid_count"] == 80 and len(home["unknown_bssids"]) <= 50 + len(cfg.network("home").bssids)
    assert "02:00:00:00:00:4F" in home["unknown_bssids"]  # most recently seen are kept
    detail = next(i["detail"] for i in home["items"] if i["title"].startswith("unregistered"))
    assert detail.endswith("(+60 more)")  # the real total, not the capped query


def test_unreadable_database_degrades_gracefully(tmp_path, monkeypatch):
    import sqlite3

    import daybreak.dashboard.app as dash

    cfg = _replayed(tmp_path)

    def refuse(*a, **kw):
        raise sqlite3.OperationalError("unable to open database file")

    monkeypatch.setattr(dash.Database, "_connect_readonly", staticmethod(refuse))
    c = TestClient(create_app(cfg), base_url="http://127.0.0.1")
    status = c.get("/api/status")
    assert status.status_code == 200 and status.json()["database"] == "unreadable"
    r = c.get("/api/alerts")
    assert r.status_code == 503 and "cannot be read" in r.json()["detail"]
    assert "default-src 'self'" in r.headers["content-security-policy"]
