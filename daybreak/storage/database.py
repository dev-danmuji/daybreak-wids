"""SQLite persistence. Stores metadata only; see :mod:`daybreak.models`."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

from ..fileperm import private_dir, secure_path
from ..models import Alert, Event, EventType, Severity, clean_text, sanitize_metadata
from .migrations import migrate


def _dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


class Database:
    """Thread-safe wrapper around one SQLite connection (WAL mode)."""

    def __init__(self, path: str | Path, *, readonly: bool = False):
        self.path = str(path)
        self.readonly = readonly
        self._lock = threading.RLock()
        if self.path != ":memory:" and not readonly:
            if Path(self.path).is_symlink():
                raise sqlite3.OperationalError(f"refusing to open a symlinked database path: {self.path}")
            private_dir(Path(self.path).parent)
        if readonly:
            self.conn = self._connect_readonly(Path(self.path))
        else:
            self.conn = sqlite3.connect(self.path, timeout=10, check_same_thread=False,
                                        isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        if not readonly:
            if self.path != ":memory:":
                self.conn.execute("PRAGMA journal_mode = WAL")
            self.conn.execute("PRAGMA synchronous = NORMAL")
            self.conn.execute("PRAGMA secure_delete = ON")  # pruned rows are overwritten, not left in free pages
            migrate(self.conn)
            if self.path != ":memory:":
                for suffix in ("", "-wal", "-shm"):  # metadata incl. MAC addresses: owner-only
                    secure_path(self.path + suffix)

    @staticmethod
    def _connect_readonly(path: Path) -> sqlite3.Connection:
        """Open without ever writing (no WAL switch, no migration, no file creation).

        ``Path.as_uri`` percent-encodes the path, so names with ``%``, ``#`` or ``?``
        cannot turn into a different (writable) URI. A WAL database whose ``-shm``
        file is gone, in a directory this user cannot write (a root-run monitor that
        has stopped), cannot be opened plainly read-only; it is then opened
        ``immutable``, which is accurate once no writer has a WAL pending.
        """
        base = path.resolve().as_uri()
        error: sqlite3.Error | None = None
        for query in ("?mode=ro", "?mode=ro&immutable=1"):
            conn = sqlite3.connect(base + query, uri=True, timeout=10, check_same_thread=False,
                                   isolation_level=None)
            try:
                conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchall()
                return conn
            except sqlite3.Error as exc:
                conn.close()
                error = exc
        assert error is not None
        raise error

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self.conn.execute("BEGIN")
            try:
                yield self.conn
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    def _query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    def _execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self.conn.execute(sql, params)

    # -- networks ----------------------------------------------------------------
    def sync_networks(self, networks: Iterable[Any]) -> dict[str, int]:
        """Upsert protected networks from configuration; returns name -> id."""
        now = time.time()
        ids: dict[str, int] = {}
        with self.transaction() as conn:
            for net in networks:
                cfg = {"bssids": list(net.bssids), "channels": list(net.channels),
                       "expected": list(net.security.expected), "pmf": net.security.pmf,
                       "origin": net.origin}
                conn.execute(
                    """INSERT INTO networks (name, ssid, status, config_json, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(name) DO UPDATE SET ssid=excluded.ssid, status=excluded.status,
                           config_json=excluded.config_json, updated_at=excluded.updated_at""",
                    (net.name, net.ssid, net.status, _dumps(cfg), now, now),
                )
                ids[net.name] = conn.execute("SELECT id FROM networks WHERE name=?",
                                             (net.name,)).fetchone()[0]
        return ids

    def list_networks(self) -> list[dict[str, Any]]:
        rows = self._query("SELECT * FROM networks ORDER BY name")
        out = []
        for r in rows:
            d = dict(r)
            d["config"] = json.loads(d.pop("config_json") or "{}")
            out.append(d)
        return out

    def network_id(self, name: str | None) -> int | None:
        if not name:
            return None
        rows = self._query("SELECT id FROM networks WHERE name=?", (name,))
        return rows[0][0] if rows else None

    # -- events --------------------------------------------------------------------
    @staticmethod
    def _event_row(event: Event) -> tuple[Any, ...]:
        md = sanitize_metadata(event.metadata)
        if event.protected is not None:
            md["protected"] = event.protected
        if event.ssid:
            md["ssid"] = event.ssid
        return (
            event.timestamp, clean_text(event.sensor or ""), event.event_type.value, event.bssid,
            event.station, event.source, event.destination, event.channel, event.rssi,
            event.reason_code, _dumps(md),
        )

    def insert_event(self, event: Event) -> int:
        cur = self._execute(
            """INSERT INTO events (timestamp, sensor, event_type, bssid, station, source,
                   destination, channel, rssi, reason_code, metadata_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            self._event_row(event),
        )
        return int(cur.lastrowid)

    def insert_events(self, events: Sequence[Event]) -> int:
        if not events:
            return 0
        rows = [self._event_row(e) for e in events]
        with self.transaction() as conn:
            conn.executemany(
                """INSERT INTO events (timestamp, sensor, event_type, bssid, station, source,
                       destination, channel, rssi, reason_code, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )
        return len(rows)

    def query_events(self, *, since: float | None = None, until: float | None = None,
                     event_types: Sequence[str] | None = None, bssids: Sequence[str] | None = None,
                     limit: int | None = None, newest_first: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []
        if since is not None:
            sql += " AND timestamp >= ?"
            params.append(since)
        if until is not None:
            sql += " AND timestamp < ?"
            params.append(until)
        if event_types:
            sql += f" AND event_type IN ({','.join('?' * len(event_types))})"
            params.extend(event_types)
        if bssids:
            sql += f" AND bssid IN ({','.join('?' * len(bssids))})"
            params.extend(bssids)
        sql += " ORDER BY timestamp " + ("DESC" if newest_first else "ASC") + ", id"
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))
        out = []
        for r in self._query(sql, params):
            d = dict(r)
            d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
            out.append(d)
        return out

    @staticmethod
    def event_from_row(row: Mapping[str, Any]) -> Event:
        """Rebuild a metadata :class:`Event` from an ``events`` row."""
        md = dict(row.get("metadata") or {})
        protected = md.pop("protected", None)
        ssid = md.pop("ssid", None)
        return Event(timestamp=row["timestamp"], event_type=EventType.parse(row["event_type"]),
                     sensor=row.get("sensor") or "", bssid=row.get("bssid"), source=row.get("source"),
                     destination=row.get("destination"), station=row.get("station"), channel=row.get("channel"),
                     rssi=row.get("rssi"), reason_code=row.get("reason_code"), protected=protected, ssid=ssid,
                     metadata=sanitize_metadata(md))

    def event_counts(self, *, since: float, until: float | None = None,
                     bssids: Sequence[str] | None = None) -> dict[str, int]:
        sql = "SELECT event_type, COUNT(*) FROM events WHERE timestamp >= ?"
        params: list[Any] = [since]
        if until is not None:
            sql += " AND timestamp < ?"
            params.append(until)
        if bssids:
            sql += f" AND bssid IN ({','.join('?' * len(bssids))})"
            params.extend(bssids)
        sql += " GROUP BY event_type"
        return {r[0]: int(r[1]) for r in self._query(sql, params)}

    def event_buckets(self, *, since: float, until: float, bucket: float,
                      event_types: Sequence[str] = ()) -> dict[int, dict[str, int]]:
        """Event counts per time bucket and type, aggregated in SQL (no rows are loaded)."""
        sql = ("SELECT CAST((timestamp - ?) / ? AS INTEGER) AS b, event_type, COUNT(*) FROM events "
               "WHERE timestamp >= ? AND timestamp < ?")
        params: list[Any] = [since, bucket, since, until]
        if event_types:
            sql += f" AND event_type IN ({','.join('?' * len(event_types))})"
            params.extend(event_types)
        sql += " GROUP BY b, event_type"
        out: dict[int, dict[str, int]] = {}
        for b, etype, count in self._query(sql, params):
            out.setdefault(int(b), {})[etype] = int(count)
        return out

    def event_time_range(self) -> tuple[float, float] | None:
        row = self._query("SELECT MIN(timestamp), MAX(timestamp) FROM events")[0]
        return (row[0], row[1]) if row[0] is not None else None

    # -- APs / stations ---------------------------------------------------------------
    def upsert_ap(self, *, bssid: str, ssid: str | None, network_id: int | None,
                  authorized: bool | None, channel: int | None, security: Any, phy: Mapping | None,
                  rssi: int | None, timestamp: float) -> None:
        sec_json = _dumps(security.to_dict()) if security is not None else None
        self._execute(
            """INSERT INTO aps (bssid, ssid, network_id, authorized, channel, security_mode, pmf,
                   security_json, phy_json, rssi_last, observations, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
               ON CONFLICT(bssid, ssid) DO UPDATE SET
                   network_id=COALESCE(excluded.network_id, aps.network_id),
                   authorized=excluded.authorized,
                   channel=COALESCE(excluded.channel, aps.channel),
                   security_mode=COALESCE(excluded.security_mode, aps.security_mode),
                   pmf=COALESCE(excluded.pmf, aps.pmf),
                   security_json=COALESCE(excluded.security_json, aps.security_json),
                   phy_json=COALESCE(excluded.phy_json, aps.phy_json),
                   rssi_last=COALESCE(excluded.rssi_last, aps.rssi_last),
                   observations=aps.observations + 1,
                   last_seen=MAX(aps.last_seen, excluded.last_seen)""",
            (bssid, clean_text(ssid or ""), network_id, None if authorized is None else int(authorized), channel,
             security.mode if security is not None else None,
             security.pmf if security is not None else None,
             sec_json, _dumps(dict(phy)) if phy else None, rssi, timestamp, timestamp),
        )

    def list_aps(self, *, ssid: str | None = None, network_id: int | None = None,
                 limit: int | None = None) -> list[dict[str, Any]]:
        """APs ordered by SSID, registered first, then BSSID.

        With ``limit``, registered APs and then the most recently seen others are kept
        (a beacon flood with random BSSIDs cannot make the result unbounded).
        """
        sql = "SELECT * FROM aps WHERE 1=1"
        params: list[Any] = []
        if ssid is not None:
            sql += " AND ssid = ?"
            params.append(ssid)
        if network_id is not None:
            sql += " AND network_id = ?"
            params.append(network_id)
        if limit:
            sql += " ORDER BY COALESCE(authorized, 0) DESC, last_seen DESC LIMIT ?"
            params.append(int(limit))
            rows = sorted(self._query(sql, params), key=lambda r: (r["ssid"], -(r["authorized"] or 0), r["bssid"]))
        else:
            sql += " ORDER BY ssid, authorized DESC, bssid"
            rows = self._query(sql, params)
        out = []
        for r in rows:
            d = dict(r)
            d["security"] = json.loads(d.pop("security_json") or "null")
            d["phy"] = json.loads(d.pop("phy_json") or "null")
            out.append(d)
        return out

    def count_aps(self, *, ssid: str, exclude_bssids: Sequence[str] = ()) -> int:
        sql = "SELECT COUNT(*) FROM aps WHERE ssid = ?"
        params: list[Any] = [ssid]
        if exclude_bssids:
            sql += f" AND bssid NOT IN ({','.join('?' * len(exclude_bssids))})"
            params.extend(exclude_bssids)
        return int(self._query(sql, params)[0][0])

    def upsert_station(self, *, mac: str, bssid: str | None, network_id: int | None,
                       timestamp: float, eapol: int = 0, disconnect: int = 0, connect: int = 0) -> None:
        self._execute(
            """INSERT INTO stations (mac, bssid, network_id, first_seen, last_seen,
                   eapol_events, disconnect_events, connect_events)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(mac, bssid) DO UPDATE SET
                   network_id=COALESCE(excluded.network_id, stations.network_id),
                   last_seen=MAX(stations.last_seen, excluded.last_seen),
                   eapol_events=stations.eapol_events + excluded.eapol_events,
                   disconnect_events=stations.disconnect_events + excluded.disconnect_events,
                   connect_events=stations.connect_events + excluded.connect_events""",
            (mac, bssid or "", network_id, timestamp, timestamp, eapol, disconnect, connect),
        )

    def list_stations(self, *, bssid: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        if bssid:
            rows = self._query("SELECT * FROM stations WHERE bssid=? ORDER BY last_seen DESC LIMIT ?",
                               (bssid, limit))
        else:
            rows = self._query("SELECT * FROM stations ORDER BY last_seen DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    # -- alerts -------------------------------------------------------------------------
    def insert_alert(self, alert: Alert) -> int:
        cur = self._execute(
            """INSERT INTO alerts (timestamp, severity, alert_type, network_id, score, reason_json,
                   acknowledged, bssid, summary, sensor, suppressed_count, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (alert.timestamp, alert.severity.name, alert.alert_type, alert.network_id, alert.score,
             _dumps(alert.reason_dict()), int(alert.acknowledged), alert.bssid, clean_text(alert.summary or ""),
             clean_text(alert.sensor or ""), alert.suppressed_count, alert.timestamp),
        )
        alert.id = int(cur.lastrowid)
        return alert.id

    def note_suppressed(self, alert_id: int, timestamp: float) -> None:
        self._execute(
            "UPDATE alerts SET suppressed_count = suppressed_count + 1, "
            "last_seen = MAX(COALESCE(last_seen, 0), ?) WHERE id = ?",
            (timestamp, alert_id),
        )

    def list_alerts(self, *, since: float | None = None, until: float | None = None,
                    min_severity: Severity | None = None, alert_type: str | None = None,
                    unacknowledged: bool = False, limit: int | None = 50) -> list[dict[str, Any]]:
        sql = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []
        if since is not None:
            sql += " AND timestamp >= ?"
            params.append(since)
        if until is not None:
            sql += " AND timestamp <= ?"
            params.append(until)
        if min_severity is not None:
            allowed = [s.name for s in Severity if s >= min_severity]
            sql += f" AND severity IN ({','.join('?' * len(allowed))})"
            params.extend(allowed)
        if alert_type:
            sql += " AND alert_type = ?"
            params.append(alert_type)
        if unacknowledged:
            sql += " AND acknowledged = 0"
        sql += " ORDER BY timestamp DESC, id DESC"
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))
        out = []
        for r in self._query(sql, params):
            d = dict(r)
            d["reason"] = json.loads(d.pop("reason_json") or "{}")
            out.append(d)
        return out

    def acknowledge_alert(self, alert_id: int) -> bool:
        cur = self._execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
        return cur.rowcount > 0

    def alert_counts(self, *, since: float | None = None) -> dict[str, int]:
        sql = "SELECT severity, COUNT(*) FROM alerts"
        params: list[Any] = []
        if since is not None:
            sql += " WHERE timestamp >= ?"
            params.append(since)
        sql += " GROUP BY severity"
        return {r[0]: int(r[1]) for r in self._query(sql, params)}

    # -- baselines ---------------------------------------------------------------------------
    def save_baseline(self, *, network_id: int | None, window_start: float, window_end: float,
                      metrics: Mapping[str, Any]) -> int:
        with self.transaction() as conn:
            if network_id is None:
                conn.execute("UPDATE baselines SET active = 0 WHERE network_id IS NULL")
            else:
                conn.execute("UPDATE baselines SET active = 0 WHERE network_id = ?", (network_id,))
            cur = conn.execute(
                """INSERT INTO baselines (network_id, created_at, window_start, window_end,
                       metrics_json, active) VALUES (?, ?, ?, ?, ?, 1)""",
                (network_id, time.time(), window_start, window_end, _dumps(dict(metrics))),
            )
            return int(cur.lastrowid)

    def active_baselines(self) -> list[dict[str, Any]]:
        rows = self._query(
            """SELECT b.*, n.name AS network FROM baselines b
               LEFT JOIN networks n ON n.id = b.network_id
               WHERE b.active = 1 ORDER BY n.name""")
        out = []
        for r in rows:
            d = dict(r)
            d["metrics"] = json.loads(d.pop("metrics_json") or "{}")
            out.append(d)
        return out

    def list_baselines(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._query(
            """SELECT b.id, b.network_id, n.name AS network, b.created_at, b.window_start,
                      b.window_end, b.active FROM baselines b
               LEFT JOIN networks n ON n.id = b.network_id
               ORDER BY b.created_at DESC LIMIT ?""", (limit,))
        return [dict(r) for r in rows]

    # -- sensor status ---------------------------------------------------------------------------
    def record_sensor_status(self, *, sensor: str, interface: str | None, status: str,
                             backend: str | None, details: Mapping[str, Any] | None = None,
                             timestamp: float | None = None) -> int:
        cur = self._execute(
            """INSERT INTO sensor_status (timestamp, sensor, interface, status, backend, details_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (timestamp or time.time(), clean_text(sensor or ""), clean_text(interface) if interface else interface,
             status, backend, _dumps(dict(details or {}))),
        )
        return int(cur.lastrowid)

    def latest_sensor_status(self, limit: int = 1) -> list[dict[str, Any]]:
        rows = self._query("SELECT * FROM sensor_status ORDER BY timestamp DESC, id DESC LIMIT ?",
                           (limit,))
        out = []
        for r in rows:
            d = dict(r)
            d["details"] = json.loads(d.pop("details_json") or "{}")
            out.append(d)
        return out

    # -- maintenance -----------------------------------------------------------------------------
    def prune(self, *, older_than: float) -> dict[str, int]:
        """Retention: delete events, alerts and sensor status older than ``older_than`` and
        station / AP records not seen since. Networks and baselines are kept."""
        statements = {
            "events": "DELETE FROM events WHERE timestamp < ?",
            "alerts": "DELETE FROM alerts WHERE COALESCE(last_seen, timestamp) < ?",
            "sensor_status": "DELETE FROM sensor_status WHERE timestamp < ?",
            "stations": "DELETE FROM stations WHERE last_seen < ?",
            "aps": "DELETE FROM aps WHERE last_seen < ?",
        }
        with self.transaction() as conn:
            return {table: conn.execute(sql, (older_than,)).rowcount for table, sql in statements.items()}

    def table_names(self) -> list[str]:
        return [r[0] for r in self._query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
