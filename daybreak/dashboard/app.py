"""Optional local dashboard (FastAPI). Read-only; binds to 127.0.0.1 by default.

All endpoints are GET and read the SQLite database / monitor status file.
Requests are only accepted for loopback host names (DNS-rebinding protection)
unless ``dashboard.allow_remote`` is set.
"""

from __future__ import annotations

import ipaddress
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __version__
from ..config import Config
from ..detectors.security import audit_network, observations_from_rows
from ..models import Severity
from ..monitor import read_status, status_path
from ..scoring import threat_level
from ..storage import Database

STATIC = Path(__file__).parent / "static"
LOOPBACK_HOSTS = ["127.0.0.1", "localhost", "::1", "[::1]"]
KNOWN_ADAPTERS = {"0e8d:7961": "MediaTek MT7921U"}


def _open_db(config: Config) -> Database | None:
    path = config.database_path
    if not path.exists():
        return None
    try:
        return Database(path, readonly=True)
    except sqlite3.OperationalError:
        return Database(path)  # WAL shared memory missing: fall back (still only read here)


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


def create_app(config: Config, *, allow_remote: bool = False) -> FastAPI:
    app = FastAPI(title="daybreak-wids", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    if not allow_remote:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=LOOPBACK_HOSTS)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        if request.method not in ("GET", "HEAD"):
            return JSONResponse({"detail": "read-only dashboard"}, status_code=405)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def db_or_none() -> Database | None:
        return _open_db(config)

    @app.get("/api/status")
    def api_status() -> dict[str, Any]:
        now = time.time()
        mon = read_status(status_path(config))
        db = db_or_none()
        last5: dict[str, int] = {}
        recent: list[dict] = []
        sensor_rows: list[dict] = []
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
            "sensor": sensor,
            "sensor_history": sensor_rows,
            "monitor": mon,
            "last5": {k: last5.get(k, 0) for k in ("deauth", "disassoc", "eapol", "auth", "assoc", "reassoc")},
            "threat_level": threat_level(recent),
            "recent_alerts": len(recent),
        }

    @app.get("/api/networks")
    def api_networks() -> list[dict[str, Any]]:
        db = db_or_none()
        out = []
        try:
            for net in config.protected_networks:
                rows = db.list_aps(ssid=net.ssid) if db else []
                audit = audit_network(net, observations_from_rows(rows)).to_dict()
                audit.update({"bssids": net.bssids, "channels": net.channels,
                              "expected": net.security.expected, "expected_pmf": net.security.pmf})
                out.append(audit)
        finally:
            if db:
                db.close()
        return out

    @app.get("/api/alerts")
    def api_alerts(hours: float = Query(24.0, gt=0, le=24 * 365), limit: int = Query(100, gt=0, le=1000),
                   min_severity: str = Query("INFO")) -> list[dict[str, Any]]:
        try:
            sev = Severity.parse(min_severity)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        db = db_or_none()
        if db is None:
            return []
        try:
            return db.list_alerts(since=time.time() - hours * 3600, min_severity=sev, limit=limit)
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
            rows = db.query_events(since=start, until=end,
                                   event_types=["deauth", "disassoc", "eapol", "auth", "assoc", "reassoc"])
            buckets: dict[int, dict[str, int]] = {}
            for r in rows:
                idx = int((r["timestamp"] - start) // 60)
                b = buckets.setdefault(idx, {})
                b[r["event_type"]] = b.get(r["event_type"], 0) + 1
            series = [{"t": start + i * 60, **buckets.get(i, {})} for i in range(minutes)]
            alerts = [{"t": a["timestamp"], "severity": a["severity"], "type": a["alert_type"], "score": a["score"]}
                      for a in db.list_alerts(since=start, limit=500) if a["timestamp"] <= end]
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
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def serve(config: Config, *, host: str, port: int, allow_remote: bool = False) -> None:
    import uvicorn

    if not is_loopback(host) and not allow_remote:
        raise ValueError(f"refusing to bind the dashboard to {host}: set dashboard.allow_remote to expose it")
    print(f"daybreak-wids dashboard on http://{host}:{port}/ (read-only; Ctrl-C to stop)")
    uvicorn.run(create_app(config, allow_remote=allow_remote), host=host, port=port, log_level="warning")
