import json
import sqlite3

import pytest

from daybreak.models import Alert, Event, ScoreComponent, SecurityProfile, Severity
from daybreak.storage import Database
from daybreak.storage.migrations import LATEST_VERSION, MigrationError, current_version, migrate

REQUIRED_TABLES = {"networks", "aps", "stations", "events", "alerts", "baselines", "sensor_status"}


def test_fresh_database_has_all_tables(tmp_path):
    db = Database(tmp_path / "x.db")
    assert REQUIRED_TABLES <= set(db.table_names())
    assert current_version(db.conn) == LATEST_VERSION
    cols = {r[1] for r in db.conn.execute("PRAGMA table_info(events)")}
    assert {"id", "timestamp", "sensor", "event_type", "bssid", "station", "channel", "rssi",
            "reason_code", "metadata_json"} <= cols
    cols = {r[1] for r in db.conn.execute("PRAGMA table_info(alerts)")}
    assert {"id", "timestamp", "severity", "alert_type", "network_id", "score", "reason_json",
            "acknowledged"} <= cols
    db.close()


def test_migration_is_incremental_and_idempotent(tmp_path):
    conn = sqlite3.connect(tmp_path / "m.db", isolation_level=None)
    assert migrate(conn, target=1) == [1]
    conn.execute("INSERT INTO events (timestamp, event_type) VALUES (1790000000, 'deauth')")
    indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert "idx_events_ts" not in indexes
    assert migrate(conn) == list(range(2, LATEST_VERSION + 1))
    assert migrate(conn) == []
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert "idx_events_ts" in indexes
    conn.close()


def test_newer_schema_is_refused(tmp_path):
    conn = sqlite3.connect(tmp_path / "n.db", isolation_level=None)
    conn.execute(f"PRAGMA user_version = {LATEST_VERSION + 5}")
    with pytest.raises(MigrationError, match="newer"):
        migrate(conn)


def test_failed_migration_rolls_back(tmp_path, monkeypatch):
    from daybreak.storage import migrations
    conn = sqlite3.connect(tmp_path / "f.db", isolation_level=None)
    monkeypatch.setattr(migrations, "MIGRATIONS", migrations.MIGRATIONS + [
        (LATEST_VERSION + 1, "broken", "CREATE TABLE ok_table (x); CREATE TABLE broken (")])
    monkeypatch.setattr(migrations, "LATEST_VERSION", LATEST_VERSION + 1)
    with pytest.raises(MigrationError):
        migrations.migrate(conn)
    assert current_version(conn) == LATEST_VERSION
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "ok_table" not in tables


def test_event_storage_strips_sensitive_metadata(tmp_path):
    db = Database(tmp_path / "e.db")
    e = Event.from_dict({"ts": 1790000000, "type": "eapol", "bssid": "AA:BB:CC:DD:EE:FF",
                         "station": "10:22:33:44:55:66", "eapol_msg": 1, "channel": 36})
    e.metadata["nonce"] = "ff" * 32  # a buggy backend tries to smuggle key material in
    db.insert_event(e)
    raw = db.conn.execute("SELECT metadata_json FROM events").fetchone()[0]
    assert json.loads(raw) == {"eapol_msg": 1}
    rows = db.query_events(event_types=["eapol"])
    assert rows[0]["station"] == "10:22:33:44:55:66" and rows[0]["channel"] == 36
    assert db.event_counts(since=0) == {"eapol": 1}


def test_alerts_roundtrip_and_ack(tmp_path, config):
    db = Database(tmp_path / "a.db")
    ids = db.sync_networks(config.protected_networks)
    a = Alert("DEAUTH_BURST", 1790000000, 82, [ScoreComponent(30, "deauth burst", "37 frames/5s")],
              summary="test", network="home", network_id=ids["home"], bssid="AA:BB:CC:DD:EE:FF")
    alert_id = db.insert_alert(a)
    db.note_suppressed(alert_id, 1790000010)
    rows = db.list_alerts(min_severity=Severity.HIGH)
    assert rows[0]["severity"] == "HIGH" and rows[0]["suppressed_count"] == 1
    assert rows[0]["reason"]["components"][0]["label"] == "deauth burst"
    assert db.list_alerts(min_severity=Severity.CRITICAL) == []
    assert db.acknowledge_alert(alert_id)
    assert db.list_alerts(unacknowledged=True) == []


def test_ap_station_baseline_sensor_status(tmp_path, config):
    db = Database(tmp_path / "b.db")
    ids = db.sync_networks(config.protected_networks)
    sec = SecurityProfile(privacy=True, rsn=True, akms=("SAE",), mfp_capable=True, mfp_required=True)
    for ts in (1.0e9, 1.0e9 + 1):
        db.upsert_ap(bssid="AA:BB:CC:DD:EE:FF", ssid="ExampleSSID", network_id=ids["home"],
                     authorized=True, channel=36, security=sec, phy=None, rssi=-40, timestamp=ts)
    ap = db.list_aps(ssid="ExampleSSID")[0]
    assert ap["observations"] == 2 and ap["security_mode"] == "WPA3-SAE" and ap["pmf"] == "required"
    db.upsert_station(mac="10:22:33:44:55:66", bssid="AA:BB:CC:DD:EE:FF", network_id=ids["home"],
                      timestamp=1.0e9, eapol=4)
    db.upsert_station(mac="10:22:33:44:55:66", bssid="AA:BB:CC:DD:EE:FF", network_id=ids["home"],
                      timestamp=1.0e9 + 5, disconnect=1)
    st = db.list_stations()[0]
    assert st["eapol_events"] == 4 and st["disconnect_events"] == 1
    db.save_baseline(network_id=ids["home"], window_start=1, window_end=2, metrics={"v": 1})
    db.save_baseline(network_id=ids["home"], window_start=3, window_end=4, metrics={"v": 2})
    active = db.active_baselines()
    assert len(active) == 1 and active[0]["metrics"] == {"v": 2} and active[0]["network"] == "home"
    db.record_sensor_status(sensor="alfa", interface="wlx00c0cab85c32", status="ONLINE",
                            backend="replay", timestamp=5)
    assert db.latest_sensor_status()[0]["status"] == "ONLINE"


def test_network_sync_is_upsert(tmp_path, config):
    db = Database(tmp_path / "s.db")
    first = db.sync_networks(config.protected_networks)
    second = db.sync_networks(config.protected_networks)
    assert first == second
    statuses = {n["name"]: n["status"] for n in db.list_networks()}
    assert statuses == {"home": "configured", "lab": "unconfigured"}
