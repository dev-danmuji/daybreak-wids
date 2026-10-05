"""Optional local dashboard (FastAPI). Read-only; binds to 127.0.0.1 by default.

All endpoints are GET and read the SQLite database / monitor status file; each
response is built from an explicit field allow-list. Requests are accepted only
for allowed Host names (DNS-rebinding protection): the loopback names, a
loopback bind address, and, with ``dashboard.allow_remote``, the bind address
and ``dashboard.allowed_hosts``. There is no authentication.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Mapping

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __version__
from ..config import Config, is_loopback_host
from ..detectors.security import audit_network, observations_from_rows
from ..models import Severity
from ..monitor import read_status, status_path
from ..scoring import threat_level
from ..storage import Database

STATIC = Path(__file__).parent / "static"
LOOPBACK_HOSTS = ["127.0.0.1", "localhost", "[::1]"]
WILDCARD_HOSTS = {"", "0.0.0.0", "::"}
KNOWN_ADAPTERS = {"0e8d:7961": "MediaTek MT7921U"}
EVENT_TYPES = ["deauth", "disassoc", "eapol", "auth", "assoc", "reassoc"]
UNKNOWN_BSSID_LIMIT = 50
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
ALERT_FIELDS = ("id", "timestamp", "severity", "alert_type", "score", "bssid", "summary",
                "suppressed_count", "acknowledged")
NETWORK_FIELDS = ("network", "ssid", "status", "mode", "transition_mode", "pmf", "pmf_required", "wps",
                  "aps", "items", "recommendations", "worst_level")

log = logging.getLogger(__name__)


class DatabaseUnavailable(Exception):
    """The database exists but cannot be read by this process."""


def _open_db(config: Config) -> Database | None:
    path = config.database_path
    if not path.exists():
        return None
    try:
        return Database(path, readonly=True)
    except sqlite3.Error as exc:
        raise DatabaseUnavailable(str(exc)) from exc


def _sensor_info(config: Config, sysfs: Path = Path("/sys/class/net")) -> dict[str, Any]:
    iface = config.sensor.interface
    base = sysfs / iface
    info: dict[str, Any] = {"interface": iface, "present": base.exists()}
    try:
        info["driver"] = os.path.basename(os.path.realpath(base / "device" / "driver"))
        dev = Path(os.path.realpath(base / "device"))
        for cand in (dev, dev.parent):
            if (cand / "idVendor").exists():
                usb = f"{(cand / 'idVendor').read_text().strip()}:{(cand / 'idProduct').read_text().strip()}"
                info["usb_id"] = usb
                info["model"] = KNOWN_ADAPTERS.get(usb)
                break
        info["type"] = {"803": "monitor", "1": "managed"}.get((base / "type").read_text().strip(), "other")
    except OSError:
        pass
    return info


def _monitor_view(mon: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """What the UI shows about the monitor; no PID, config path or backend error text."""
    if not mon:
        return None
    backend = mon.get("backend") or {}
    return {"state": mon.get("state"), "alive": mon.get("alive"), "updated": mon.get("updated"),
            "last_event": mon.get("last_event"), "threat_level": mon.get("threat_level"),
            "backend": {"name": backend.get("name"), "healthy": backend.get("healthy")}}


def _alert_view(alert: Mapping[str, Any]) -> dict[str, Any]:
    """Alert fields shown by the UI: the score explanation, not the station list or details."""
    out = {k: alert.get(k) for k in ALERT_FIELDS}
    comps = (alert.get("reason") or {}).get("components") or []
    out["reason"] = {"components": [{"points": c.get("points"), "label": c.get("label"),
                                     "detail": c.get("detail")} for c in comps]}
    return out


def host_header_name(host: str) -> str:
    """Host-header form of an address (IPv6 literals are bracketed)."""
    bare = host.strip().strip("[]")
    try:
        if ipaddress.ip_address(bare).version == 6:
            return f"[{bare}]"
    except ValueError:
        pass
    return bare


def allowed_hosts(config: Config, bind_host: str | None = None, *, allow_remote: bool = False) -> list[str]:
    hosts = list(LOOPBACK_HOSTS)
    bind = (config.dashboard.host if bind_host is None else bind_host).strip()
    if bind.strip("[]") not in WILDCARD_HOSTS and (allow_remote or is_loopback_host(bind)):
        hosts.append(host_header_name(bind))
    if allow_remote:
        hosts += [host_header_name(h) for h in config.dashboard.allowed_hosts]
    return list(dict.fromkeys(hosts))


def create_app(config: Config, *, allow_remote: bool = False, bind_host: str | None = None) -> FastAPI:
    app = FastAPI(title="daybreak-wids", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    # Always on, also with allow_remote: only the configured names are served (DNS rebinding).
    app.add_middleware(TrustedHostMiddleware,
                       allowed_hosts=allowed_hosts(config, bind_host, allow_remote=allow_remote))

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        if request.method not in ("GET", "HEAD"):
            response = JSONResponse({"detail": "read-only dashboard"}, status_code=405,
                                    headers={"Allow": "GET, HEAD"})
        else:
            try:
                response = await call_next(request)
            except Exception:  # no traceback to the client, and keep the security headers
                log.exception("dashboard request failed")
                response = JSONResponse({"detail": "internal error"}, status_code=500)
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.exception_handler(DatabaseUnavailable)
    async def database_unavailable(request: Request, exc: DatabaseUnavailable) -> JSONResponse:  # noqa: ARG001
        return JSONResponse({"detail": "the database cannot be read by the dashboard process "
                                       "(written by another user? see README: file locations)"},
                            status_code=503)

    def db_or_none() -> Database | None:
        return _open_db(config)

    @app.get("/api/status")
    def api_status() -> dict[str, Any]:
        now = time.time()
        mon = read_status(status_path(config))
        last5: dict[str, int] = {}
        recent: list[dict] = []
        sensor_rows: list[dict] = []
        try:
            db = db_or_none()
            database = "ok" if db is not None else "missing"
        except DatabaseUnavailable:
            db, database = None, "unreadable"
        if db is not None:
            try:
                last5 = db.event_counts(since=now - 300)
                recent = db.list_alerts(since=now - 300, limit=200)
                sensor_rows = db.latest_sensor_status(limit=5)
            finally:
                db.close()
        sensor = _sensor_info(config)
        if mon:
            sensor["online"] = (mon.get("sensor") or {}).get("online")
        return {
            "generated": now,
            "database": database,
            "sensor": sensor,
            "sensor_history": [{"timestamp": r["timestamp"], "status": r["status"]} for r in sensor_rows],
            "monitor": _monitor_view(mon),
            "last5": {k: last5.get(k, 0) for k in EVENT_TYPES},
            "threat_level": threat_level(recent),
            "recent_alerts": len(recent),
        }

    @app.get("/api/networks")
    def api_networks() -> list[dict[str, Any]]:
        db = db_or_none()
        out = []
        try:
            for net in config.protected_networks:
                rows = db.list_aps(ssid=net.ssid, limit=UNKNOWN_BSSID_LIMIT + len(net.bssids)) if db else []
                unknown = db.count_aps(ssid=net.ssid, exclude_bssids=net.bssids) if db else 0
                audit = audit_network(net, observations_from_rows(rows), unknown_total=unknown).to_dict()
                view = {k: audit[k] for k in NETWORK_FIELDS}
                view.update({
                    "unknown_bssids": audit["unknown_bssids"],  # bounded by the query: most recent first
                    "unknown_bssid_count": unknown,
                    "bssids": net.bssids, "channels": net.channels,
                    "expected": net.security.expected, "expected_pmf": net.security.pmf,
                })
                out.append(view)
        finally:
            if db:
                db.close()
        return out

    @app.get("/api/alerts")
    def api_alerts(hours: float = Query(24.0, gt=0, le=24 * 365), limit: int = Query(100, gt=0, le=1000),
                   min_severity: str = Query("INFO"),
                   until: float | None = Query(None, gt=0, le=4_102_444_800)) -> list[dict[str, Any]]:
        try:
            sev = Severity.parse(min_severity)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        db = db_or_none()
        if db is None:
            return []
        try:
            end = time.time() if until is None else until
            rows = db.list_alerts(since=end - hours * 3600, until=until, min_severity=sev, limit=limit)
            return [_alert_view(a) for a in rows]
        finally:
            db.close()

    @app.get("/api/timeline")
    def api_timeline(minutes: int = Query(60, gt=0, le=24 * 60)) -> dict[str, Any]:
        db = db_or_none()
        if db is None:
            return {"anchor": None, "buckets": [], "alerts": []}
        try:
            end = time.time()
            if not db.event_counts(since=end - minutes * 60):
                rng = db.event_time_range()
                if rng:  # no live data: show the most recent recorded period (e.g. a replay)
                    end = rng[1] + 1
            start = end - minutes * 60
            counts = db.event_buckets(since=start, until=end, bucket=60, event_types=EVENT_TYPES)
            series = [{"t": start + i * 60, **counts.get(i, {})} for i in range(minutes)]
            alerts = [{"t": a["timestamp"], "severity": a["severity"], "type": a["alert_type"], "score": a["score"]}
                      for a in db.list_alerts(since=start, until=end, limit=500)]
            return {"anchor": end, "start": start, "buckets": series, "alerts": alerts}
        finally:
            db.close()

    @app.get("/api/baseline")
    def api_baseline() -> list[dict[str, Any]]:
        db = db_or_none()
        if db is None:
            return []
        try:
            out = []
            for b in db.active_baselines():
                m = b["metrics"]
                out.append({"network": b["network"], "created": b["created_at"], "window": m.get("window"),
                            "rates": m.get("rates"), "clients": m.get("clients"), "security": m.get("security"),
                            "known_bssids": m.get("known_bssids"), "known_channels": m.get("known_channels")})
            return out
        finally:
            db.close()

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @app.get("/static/{name}")
    def static(name: str) -> FileResponse:
        allowed = {"app.js": "text/javascript", "style.css": "text/css"}
        if name not in allowed:
            raise HTTPException(404)
        return FileResponse(STATIC / name, media_type=allowed[name])

    return app


def is_loopback(host: str) -> bool:
    return is_loopback_host(host)


def serve(config: Config, *, host: str, port: int, allow_remote: bool = False) -> None:
    import uvicorn

    if not is_loopback(host):
        if not allow_remote:
            raise ValueError(f"refusing to bind the dashboard to {host}: set dashboard.allow_remote to expose it")
        if host.strip().strip("[]") in WILDCARD_HOSTS and not config.dashboard.allowed_hosts:
            raise ValueError(f"binding the dashboard to {host!r} needs dashboard.allowed_hosts: the host names "
                             "or addresses you will type in the browser (Host-header allow-list)")
        print(f"WARNING: the dashboard has no authentication; anyone who can reach {host}:{port} can read "
              "alerts, MAC addresses and network names", file=sys.stderr)
    print(f"daybreak-wids dashboard on http://{host_header_name(host)}:{port}/ (read-only; Ctrl-C to stop)")
    uvicorn.run(create_app(config, allow_remote=allow_remote, bind_host=host), host=host.strip().strip("[]"),
                port=port, log_level="warning", limit_concurrency=32)
