"""Versioned SQLite schema migrations (tracked with ``PRAGMA user_version``)."""

from __future__ import annotations

import sqlite3

# (version, description, SQL). Never edit a released migration; append a new one.
MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "initial schema", """
        CREATE TABLE networks (
            id          INTEGER PRIMARY KEY,
            name        TEXT NOT NULL UNIQUE,
            ssid        TEXT NOT NULL,
            status      TEXT NOT NULL,
            config_json TEXT NOT NULL DEFAULT '{}',
            created_at  REAL NOT NULL,
            updated_at  REAL NOT NULL
        );

        CREATE TABLE aps (
            id            INTEGER PRIMARY KEY,
            bssid         TEXT NOT NULL,
            ssid          TEXT NOT NULL DEFAULT '',
            network_id    INTEGER REFERENCES networks(id) ON DELETE SET NULL,
            authorized    INTEGER,
            channel       INTEGER,
            security_mode TEXT,
            pmf           TEXT,
            security_json TEXT,
            phy_json      TEXT,
            rssi_last     INTEGER,
            observations  INTEGER NOT NULL DEFAULT 0,
            first_seen    REAL NOT NULL,
            last_seen     REAL NOT NULL,
            UNIQUE (bssid, ssid)
        );

        CREATE TABLE stations (
            id                INTEGER PRIMARY KEY,
            mac               TEXT NOT NULL,
            bssid             TEXT NOT NULL DEFAULT '',
            network_id        INTEGER REFERENCES networks(id) ON DELETE SET NULL,
            first_seen        REAL NOT NULL,
            last_seen         REAL NOT NULL,
            eapol_events      INTEGER NOT NULL DEFAULT 0,
            disconnect_events INTEGER NOT NULL DEFAULT 0,
            connect_events    INTEGER NOT NULL DEFAULT 0,
            UNIQUE (mac, bssid)
        );

        CREATE TABLE events (
            id            INTEGER PRIMARY KEY,
            timestamp     REAL NOT NULL,
            sensor        TEXT NOT NULL DEFAULT '',
            event_type    TEXT NOT NULL,
            bssid         TEXT,
            station       TEXT,
            source        TEXT,
            destination   TEXT,
            channel       INTEGER,
            rssi          INTEGER,
            reason_code   INTEGER,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE alerts (
            id               INTEGER PRIMARY KEY,
            timestamp        REAL NOT NULL,
            severity         TEXT NOT NULL,
            alert_type       TEXT NOT NULL,
            network_id       INTEGER REFERENCES networks(id) ON DELETE SET NULL,
            score            INTEGER NOT NULL,
            reason_json      TEXT NOT NULL,
            acknowledged     INTEGER NOT NULL DEFAULT 0,
            bssid            TEXT,
            summary          TEXT NOT NULL DEFAULT '',
            sensor           TEXT NOT NULL DEFAULT '',
            suppressed_count INTEGER NOT NULL DEFAULT 0,
            last_seen        REAL
        );

        CREATE TABLE baselines (
            id           INTEGER PRIMARY KEY,
            network_id   INTEGER REFERENCES networks(id) ON DELETE CASCADE,
            created_at   REAL NOT NULL,
            window_start REAL NOT NULL,
            window_end   REAL NOT NULL,
            metrics_json TEXT NOT NULL,
            active       INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE sensor_status (
            id           INTEGER PRIMARY KEY,
            timestamp    REAL NOT NULL,
            sensor       TEXT NOT NULL,
            interface    TEXT,
            status       TEXT NOT NULL,
            backend      TEXT,
            details_json TEXT NOT NULL DEFAULT '{}'
        );
    """),
    (2, "query indexes", """
        CREATE INDEX idx_events_ts        ON events (timestamp);
        CREATE INDEX idx_events_bssid_ts  ON events (bssid, timestamp);
        CREATE INDEX idx_events_type_ts   ON events (event_type, timestamp);
        CREATE INDEX idx_alerts_ts        ON alerts (timestamp);
        CREATE INDEX idx_alerts_type_ts   ON alerts (alert_type, timestamp);
        CREATE INDEX idx_sensor_status_ts ON sensor_status (timestamp);
        CREATE INDEX idx_baselines_active ON baselines (network_id, active);
    """),
]

LATEST_VERSION = MIGRATIONS[-1][0]


class MigrationError(RuntimeError):
    pass


def current_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def migrate(conn: sqlite3.Connection, target: int | None = None) -> list[int]:
    """Apply pending migrations up to ``target`` (default: latest). Returns applied versions."""
    target = LATEST_VERSION if target is None else target
    version = current_version(conn)
    if version > LATEST_VERSION:
        raise MigrationError(
            f"database schema v{version} is newer than this daybreak-wids (v{LATEST_VERSION})"
        )
    applied = []
    for number, _description, sql in MIGRATIONS:
        if number <= version or number > target:
            continue
        try:
            conn.execute("BEGIN IMMEDIATE")
            for statement in _split_sql(sql):
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {int(number)}")
            conn.execute("COMMIT")
        except sqlite3.Error as exc:
            conn.execute("ROLLBACK")
            raise MigrationError(f"migration {number} failed: {exc}") from exc
        applied.append(number)
    return applied


def _split_sql(sql: str) -> list[str]:
    return [s.strip() for s in sql.split(";") if s.strip()]
