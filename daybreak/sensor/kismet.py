"""Kismet integration (REST + optional eventbus).

Kismet is the preferred sensor backend: it manages the capture source and
channel hopping and already implements WIDS alerts (DEAUTHFLOOD, BCASTDISCON,
APSPOOF, CRYPTODROP, ...). daybreak-wids consumes those alerts and Kismet's AP
security records instead of re-implementing them.

Only read-only endpoints are used (a ``readonly`` API key is sufficient), and
device records are requested through field simplification with an explicit
allow-list, so handshake/PMKID/nonce data is never requested from Kismet.
"""

from __future__ import annotations

import base64
import json
import os
import queue
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from ..config import Config, KismetConfig, is_loopback_host
from ..models import Event, EventType, SecurityProfile, try_normalize_mac
from .backend import Backend, BackendStatus, BackendUnavailable
from .discovery import freq_to_channel


class KismetError(RuntimeError):
    pass


class KismetUnavailable(KismetError):
    """Kismet is not reachable (not installed, not running, wrong URL)."""


class KismetAuthError(KismetError):
    """Kismet rejected the credentials (401/403)."""


# Kismet WIDS alerts daybreak-wids builds on (checked by `daybreak-wids kismet check`).
REQUESTED_WIDS_ALERTS = (
    "DEAUTHFLOOD", "BCASTDISCON", "DISASSOCTRAFFIC", "DISCONCODEINVALID",
    "APSPOOF", "ADVCRYPTCHANGE", "CRYPTODROP", "CHANCHANGE",
)
WIDS_ALERTS = REQUESTED_WIDS_ALERTS + ("DEAUTHCODEINVALID", "NOCLIENTMFP")

# Read-only endpoints used by this module (verified by tests).
ENDPOINTS = {
    "status": "/system/status.json",
    "datasources": "/datasource/all_sources.json",
    "alert_definitions": "/alerts/definitions.json",
    "alerts_since": "/alerts/wrapped/last-time/{ts}/alerts.json",
    "devices_since": "/devices/last-time/{ts}/devices.json",
    "active_logs": "/logging/active.json",
}

_SSID = "dot11.device/dot11.device.last_beaconed_ssid_record/"
# [kismet field path, local name] -- the complete list of device fields we request.
SAFE_DEVICE_FIELDS: list[list[str]] = [
    ["kismet.device.base.macaddr", "mac"],
    ["kismet.device.base.type", "type"],
    ["kismet.device.base.phyname", "phy"],
    ["kismet.device.base.channel", "channel"],
    ["kismet.device.base.frequency", "frequency"],
    ["kismet.device.base.last_time", "last_time"],
    ["kismet.device.base.signal/kismet.common.signal.last_signal", "signal"],
    [_SSID + "dot11.advertisedssid.ssid", "ssid"],
    [_SSID + "dot11.advertisedssid.crypt_string", "crypt_string"],
    [_SSID + "dot11.advertisedssid.wpa_mfp_required", "mfp_required"],
    [_SSID + "dot11.advertisedssid.wpa_mfp_supported", "mfp_supported"],
    [_SSID + "dot11.advertisedssid.channel", "ssid_channel"],
    [_SSID + "dot11.advertisedssid.wps_state", "wps_state"],
    ["dot11.device/dot11.device.num_associated_clients", "num_clients"],
]
SAFE_DEVICE_KEYS = frozenset(name for _, name in SAFE_DEVICE_FIELDS)

ALERT_FIELDS = {
    "header": "kismet.alert.header",
    "timestamp": "kismet.alert.timestamp",
    "bssid": "kismet.alert.transmitter_mac",
    "source": "kismet.alert.source_mac",
    "dest": "kismet.alert.dest_mac",
    "other": "kismet.alert.other_mac",
    "channel": "kismet.alert.channel",
    "frequency": "kismet.alert.frequency",
    "text": "kismet.alert.text",
    "class": "kismet.alert.class",
    "severity": "kismet.alert.severity",
    "hash": "kismet.alert.hash",
}

_ZERO_MAC = "00:00:00:00:00:00"


# ---------------------------------------------------------------------------
# REST client
# ---------------------------------------------------------------------------


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: they would carry the API key cookie / Basic auth header to
    another URL, outside the endpoint allow-list. A 3xx then surfaces as an HTTP error."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002, ANN001
        return None


class KismetClient:
    def __init__(self, url: str, *, api_key: str | None = None, username: str | None = None,
                 password: str | None = None, timeout: float = 5.0):
        self.base = url.rstrip("/")
        self.api_key = api_key
        self.username = username
        self.password = password
        self.timeout = timeout
        # Never route Kismet traffic through an HTTP proxy, and never follow redirects.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RefuseRedirects())

    @classmethod
    def from_config(cls, cfg: KismetConfig) -> "KismetClient":
        api_key = os.environ.get(cfg.api_key_env) if cfg.api_key_env else None
        password = os.environ.get(cfg.password_env) if cfg.password_env else None
        return cls(cfg.url, api_key=api_key or None, username=cfg.username, password=password,
                   timeout=cfg.timeout)

    def auth_headers(self) -> dict[str, str]:
        """Credentials travel in headers only, never in a URL (URLs end up in server/proxy logs)."""
        if self.api_key:
            return {"Cookie": f"KISMET={self.api_key}"}
        if self.username and self.password is not None:
            token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            return {"Authorization": f"Basic {token}"}
        return {}

    def _headers(self) -> dict[str, str]:
        return {"Accept": "application/json", "User-Agent": "daybreak-wids", **self.auth_headers()}

    def request(self, path: str, *, fields: list | None = None) -> Any:
        if not any(path.startswith(p.split("{")[0]) for p in ENDPOINTS.values()):
            raise KismetError(f"endpoint not allow-listed: {path}")
        data = None
        headers = self._headers()
        if fields is not None:
            data = urllib.parse.urlencode({"json": json.dumps({"fields": fields})}).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(self.base + path, data=data, headers=headers,
                                     method="POST" if data is not None else "GET")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                body = resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise KismetAuthError(
                    f"Kismet rejected the credentials (HTTP {exc.code}); create a read-only API key "
                    "and export it as KISMET_API_KEY") from exc
            raise KismetError(f"Kismet returned HTTP {exc.code} for {path}") from exc
        except (urllib.error.URLError, ConnectionError, TimeoutError, socket.timeout, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise KismetUnavailable(f"Kismet not reachable at {self.base}: {reason}") from exc
        try:
            return json.loads(body.decode("utf-8", "replace") or "null")
        except ValueError as exc:
            raise KismetError(f"invalid JSON from Kismet for {path}") from exc

    # -- endpoints ----------------------------------------------------------------
    def system_status(self) -> dict[str, Any]:
        data = self.request(ENDPOINTS["status"])
        if not isinstance(data, dict):
            raise KismetError("unexpected /system/status.json payload")
        return data

    def datasources(self) -> list[dict[str, Any]]:
        data = self.request(ENDPOINTS["datasources"])
        return data if isinstance(data, list) else []

    def alert_definitions(self) -> list[dict[str, Any]]:
        data = self.request(ENDPOINTS["alert_definitions"])
        return data if isinstance(data, list) else []

    def alerts_since(self, ts: float) -> tuple[list[dict[str, Any]], float | None]:
        data = self.request(ENDPOINTS["alerts_since"].format(ts=f"{ts:.6f}"))
        if isinstance(data, list):
            return data, None
        if isinstance(data, dict):
            alerts = data.get("kismet.alert.list") or []
            server_ts = data.get("kismet.alert.timestamp")
            return (alerts if isinstance(alerts, list) else []), _as_float(server_ts)
        return [], None

    def devices_since(self, ts: float) -> list[dict[str, Any]]:
        data = self.request(ENDPOINTS["devices_since"].format(ts=f"{ts:.6f}"),
                            fields=SAFE_DEVICE_FIELDS)
        if not isinstance(data, list):
            return []
        # Defence in depth: keep only allow-listed keys even if Kismet ignored simplification.
        return [{k: v for k, v in d.items() if k in SAFE_DEVICE_KEYS} for d in data if isinstance(d, dict)]

    def active_logs(self) -> list[dict[str, Any]]:
        data = self.request(ENDPOINTS["active_logs"])
        return data if isinstance(data, list) else []

    def server_time(self, status: Mapping[str, Any] | None = None) -> float | None:
        st = status if status is not None else self.system_status()
        sec = _as_float(st.get("kismet.system.timestamp.sec"))
        usec = _as_float(st.get("kismet.system.timestamp.usec")) or 0.0
        return sec + usec / 1e6 if sec else None


def _as_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Record conversion
# ---------------------------------------------------------------------------


def parse_kismet_channel(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value) if 1 <= int(value) <= 233 else None
    m = re.match(r"\s*(\d+)", str(value))
    if not m:
        return None
    ch = int(m.group(1))
    return ch if 1 <= ch <= 233 else None


def _freq_mhz(value: Any) -> int | None:
    f = _as_float(value)
    if not f:
        return None
    return int(f / 1000) if f > 100000 else int(f)


_AKM_SUFFIX = [
    ("-PSK-SHA384-FT", "FT-PSK-SHA384"), ("-PSK-SHA384", "PSK-SHA384"),
    ("-PSK-SHA256", "PSK-SHA256"), ("-PSK-FT", "FT-PSK"), ("-PSK", "PSK"),
    ("-SAE-FT", "FT-SAE"), ("-SAE", "SAE"),
    ("-EAP-SUITEB-SHA384", "802.1X-SUITE-B-192"), ("-EAP-SUITEB-SHA256", "802.1X-SUITE-B"),
    ("-EAP-FT", "FT-802.1X"), ("-EAP", "802.1X"), ("-OWE", "OWE"),
]
_CIPHERS = {
    "TKIP": "TKIP", "AES-CCMP": "CCMP-128", "AES-CCMP256": "CCMP-256", "AES-GCMP128": "GCMP-128",
    "AES-GCMP256": "GCMP-256", "AES-OCB": "OCB", "WEP40": "WEP40", "WEP104": "WEP104",
}


def kismet_security(crypt: str | None, mfp_required: Any = None, mfp_supported: Any = None,
                     wps_state: Any = None) -> SecurityProfile | None:
    """Translate Kismet's ``crypt_string`` + MFP flags into a :class:`SecurityProfile`."""
    if crypt is None:
        return None
    text = str(crypt).strip()
    if not text:
        return None
    if text.lower() == "open":
        return SecurityProfile(source="kismet")
    tokens = text.split()
    if tokens[0].upper().startswith("WEP"):
        return SecurityProfile(privacy=True, pairwise_ciphers=(tokens[0].upper(),), source="kismet")
    akms: list[str] = []
    ciphers: list[str] = []
    versions = set()
    for tok in tokens:
        up = tok.upper()
        m = re.match(r"^(WPA[123]?)", up)
        if m:
            versions.add(m.group(1))
            for suffix, akm in _AKM_SUFFIX:
                if up.endswith(suffix):
                    if akm not in akms:
                        akms.append(akm)
                    break
        elif up in _CIPHERS:
            ciphers.append(_CIPHERS[up])
    wpa1 = "WPA1" in versions or (versions == {"WPA"} and not akms)
    rsn = bool(versions & {"WPA2", "WPA3"}) or (bool(akms) and "WPA1" not in versions)
    req = bool(mfp_required)
    wps = None
    if wps_state not in (None, 0, "0", ""):
        wps = True
    return SecurityProfile(
        privacy=True, rsn=rsn, wpa1=wpa1, akms=tuple(akms), pairwise_ciphers=tuple(ciphers),
        mfp_capable=bool(mfp_supported) or req, mfp_required=req, wps=wps, source="kismet",
    )


KISMET_TEXT_MAX = 512


def _scalar_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value)) if isinstance(value, (str, float)) else None
    except ValueError:
        return None


def alert_to_event(record: Mapping[str, Any], sensor: str) -> Event | None:
    """Kismet alert record -> ``KISMET_ALERT`` event (metadata only)."""
    if not isinstance(record, Mapping):
        return None
    get = lambda key: record.get(ALERT_FIELDS[key])  # noqa: E731
    header = get("header")
    ts = _as_float(get("timestamp"))
    if not header or not ts:
        return None
    macs = {}
    for key in ("bssid", "source", "dest", "other"):
        mac = try_normalize_mac(get(key))
        macs[key] = None if mac == _ZERO_MAC else mac
    channel = parse_kismet_channel(get("channel"))
    freq = _freq_mhz(get("frequency"))
    if channel is None and freq:
        channel = freq_to_channel(freq)[0]
    md = {
        "kismet_header": str(header),
        "kismet_text": str(get("text") or "")[:KISMET_TEXT_MAX],
        "kismet_class": str(get("class") or "")[:64],
        "kismet_severity": _scalar_int(get("severity")),
        "kismet_hash": _scalar_int(get("hash")),
        "source_backend": "kismet",
    }
    if freq:
        md["frequency"] = freq
    ev = Event(
        timestamp=ts, event_type=EventType.KISMET_ALERT, sensor=sensor,
        bssid=macs["bssid"], source=macs["source"], destination=macs["dest"], channel=channel,
        metadata={k: v for k, v in md.items() if v not in (None, "")},
    )
    ev.derive_station()
    return ev


def device_to_event(record: Mapping[str, Any], sensor: str, now: float) -> Event | None:
    """Kismet (simplified) AP device record -> ``BEACON`` observation event."""
    ssid = record.get("ssid")
    mac = try_normalize_mac(record.get("mac"))
    if not mac or not isinstance(ssid, str) or not ssid:
        return None
    if record.get("crypt_string") is None and "AP" not in str(record.get("type", "")):
        return None
    channel = parse_kismet_channel(record.get("ssid_channel")) or parse_kismet_channel(record.get("channel"))
    freq = _freq_mhz(record.get("frequency"))
    if channel is None and freq:
        channel = freq_to_channel(freq)[0]
    signal = record.get("signal")
    rssi = int(signal) if isinstance(signal, (int, float)) and -127 <= signal < 0 else None
    ts = _as_float(record.get("last_time")) or now
    md: dict[str, Any] = {"source_backend": "kismet"}
    if isinstance(record.get("num_clients"), int):
        md["num_clients"] = record["num_clients"]
    if freq:
        md["frequency"] = freq
    return Event(
        timestamp=ts, event_type=EventType.BEACON, sensor=sensor, bssid=mac, source=mac,
        channel=channel, rssi=rssi, ssid=ssid[:32],
        security=kismet_security(record.get("crypt_string"), record.get("mfp_required"),
                                 record.get("mfp_supported"), record.get("wps_state")),
        metadata=md,
    )


# ---------------------------------------------------------------------------
# Datasources
# ---------------------------------------------------------------------------


@dataclass
class DatasourceInfo:
    uuid: str
    name: str
    interface: str
    capture_interface: str
    running: bool
    error: bool
    error_reason: str
    channel: str
    hopping: bool
    packets: int

    @classmethod
    def from_record(cls, r: Mapping[str, Any]) -> "DatasourceInfo":
        return cls(
            uuid=str(r.get("kismet.datasource.uuid", "")),
            name=str(r.get("kismet.datasource.name", "")),
            interface=str(r.get("kismet.datasource.interface", "")),
            capture_interface=str(r.get("kismet.datasource.capture_interface", "")),
            running=bool(r.get("kismet.datasource.running", False)),
            error=bool(r.get("kismet.datasource.error", False)),
            error_reason=str(r.get("kismet.datasource.error_reason", "") or ""),
            channel=str(r.get("kismet.datasource.channel", "") or ""),
            hopping=bool(r.get("kismet.datasource.hopping", False)),
            packets=int(r.get("kismet.datasource.num_packets", 0) or 0),
        )

    def matches(self, interface: str) -> bool:
        return interface in (self.interface, self.capture_interface) or \
            self.capture_interface.startswith(interface)


def sensor_datasource(sources: list[DatasourceInfo], interface: str) -> DatasourceInfo | None:
    return next((s for s in sources if s.matches(interface)), None)


# ---------------------------------------------------------------------------
# Eventbus (optional, needs websocket-client)
# ---------------------------------------------------------------------------

EVENTBUS_TOPICS = ("ALERT", "DATASOURCE_ERROR", "DATASOURCE_CLOSED", "DATASOURCE_OPENED")


def eventbus_url(base: str) -> str:
    """Eventbus websocket URL (no credentials: they are sent as headers, see EventbusReader)."""
    parts = urllib.parse.urlsplit(base)
    scheme = "wss" if parts.scheme == "https" else "ws"
    return urllib.parse.urlunsplit((scheme, parts.netloc, parts.path.rstrip("/") + "/eventbus/events.ws", "", ""))


class EventbusReader(threading.Thread):
    """Background reader that pushes decoded eventbus messages into a queue."""

    def __init__(self, url: str, out: "queue.Queue[dict]", *,
                 connect: Callable[[str], Any] | None = None, reconnect_delay: float = 5.0,
                 headers: dict[str, str] | None = None):
        super().__init__(name="kismet-eventbus", daemon=True)
        self.url = url
        self.out = out
        self.headers = dict(headers or {})
        self._connect = connect
        self.reconnect_delay = reconnect_delay
        self._stop = threading.Event()
        self.connected = threading.Event()
        self.last_error: str | None = None
        self._ws = None

    @staticmethod
    def available() -> bool:
        try:
            import websocket  # noqa: F401
        except ImportError:
            return False
        return True

    def _open(self):
        if self._connect is not None:
            return self._connect(self.url)
        import websocket
        # Credentials as headers; like the REST client, never through an environment proxy.
        return websocket.create_connection(self.url, timeout=10, http_no_proxy=["*"],
                                           header=[f"{k}: {v}" for k, v in self.headers.items()])

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                ws = self._ws = self._open()
                for topic in EVENTBUS_TOPICS:
                    ws.send(json.dumps({"SUBSCRIBE": topic}))
                self.connected.set()
                while not self._stop.is_set():
                    msg = ws.recv()
                    if not msg:
                        raise ConnectionError("eventbus closed")
                    try:
                        data = json.loads(msg)
                    except ValueError:
                        continue
                    if isinstance(data, dict):
                        self.out.put(data)
            except Exception as exc:  # network errors, closed sockets, ...
                self.last_error = str(exc)
            finally:
                self.connected.clear()
                try:
                    if self._ws is not None:
                        self._ws.close()
                except Exception:
                    pass
            self._stop.wait(self.reconnect_delay)

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._ws is not None:
                self._ws.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------


class KismetBackend(Backend):
    name = "kismet"

    def __init__(self, cfg: KismetConfig, *, sensor_interface: str, sensor_name: str = "",
                 client: KismetClient | None = None, clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep,
                 frame_tap_factory: Callable[[str], Backend] | None = None,
                 eventbus_connect: Callable[[str], Any] | None = None):
        super().__init__(sensor_name or sensor_interface)
        self.cfg = cfg
        self.sensor_interface = sensor_interface
        self.client = client or KismetClient.from_config(cfg)
        self.clock = clock
        self.sleep = sleep
        self.frame_tap_factory = frame_tap_factory
        self.eventbus_connect = eventbus_connect
        self.frame_tap: Backend | None = None
        self.frame_tap_error: str | None = None
        self.eventbus: EventbusReader | None = None
        self._queue: "queue.Queue[dict]" = queue.Queue()
        self.offset = 0.0  # kismet clock - local clock
        self.last_alert_ts = 0.0
        self.last_device_ts = 0.0
        self._next_alert = self._next_device = self._next_ds = 0.0
        self.datasources: list[DatasourceInfo] = []
        self.version: str | None = None
        self._healthy = False

    # -- lifecycle ------------------------------------------------------------
    def open(self) -> None:
        self.close()  # re-open after an outage: never leave a second eventbus reader running
        try:
            status = self.client.system_status()
        except KismetError as exc:
            raise BackendUnavailable(str(exc)) from exc
        self.version = str(status.get("kismet.system.version", "")) or None
        server = self.client.server_time(status) or self.clock()
        self.offset = server - self.clock()
        self.last_alert_ts = server
        self.last_device_ts = server - 60.0  # initial AP security snapshot
        self._healthy = True
        self._refresh_datasources()
        if self.cfg.use_eventbus and (self.eventbus_connect or EventbusReader.available()):
            self.eventbus = EventbusReader(eventbus_url(self.client.base), self._queue,
                                           connect=self.eventbus_connect, headers=self.client.auth_headers())
            self.eventbus.start()
        if self.cfg.frame_tap and self.frame_tap_factory is not None:
            self._open_frame_tap()

    def _open_frame_tap(self) -> None:
        ds = sensor_datasource(self.datasources, self.sensor_interface)
        iface = (ds.capture_interface or ds.interface) if ds else None
        if not iface:
            self.frame_tap_error = "no Kismet datasource for the sensor interface"
            return
        try:
            tap = self.frame_tap_factory(iface)
            tap.open()
            self.frame_tap = tap
            self.frame_tap_error = None
        except (OSError, BackendUnavailable) as exc:
            self.frame_tap = None
            self.frame_tap_error = f"frame tap on {iface} unavailable: {exc}"

    def close(self) -> None:
        if self.eventbus:
            self.eventbus.stop()
            self.eventbus = None
        if self.frame_tap:
            self.frame_tap.close()
            self.frame_tap = None

    # -- polling -----------------------------------------------------------------
    def _refresh_datasources(self) -> None:
        self.datasources = [DatasourceInfo.from_record(r) for r in self.client.datasources()
                            if isinstance(r, Mapping)]

    def _drain_eventbus(self, out: list[Event]) -> None:
        while True:
            try:
                msg = self._queue.get_nowait()
            except queue.Empty:
                return
            for topic, content in msg.items():
                if topic == "ALERT":
                    ev = alert_to_event(content, self.sensor_name)
                    if ev:
                        self.last_alert_ts = max(self.last_alert_ts, ev.timestamp)
                        out.append(ev)
                elif topic.startswith("DATASOURCE_"):
                    self._next_ds = 0.0  # refresh datasource state on the next poll

    def poll(self, timeout: float) -> list[Event]:
        out: list[Event] = []
        try:
            self._drain_eventbus(out)
            now = self.clock()
            eventbus_live = self.eventbus is not None and self.eventbus.connected.is_set()
            if now >= self._next_alert:
                self._next_alert = now + (self.cfg.poll_interval * (5 if eventbus_live else 1))
                alerts, server_ts = self.client.alerts_since(self.last_alert_ts)
                for rec in alerts:
                    ev = alert_to_event(rec, self.sensor_name)
                    if ev:
                        out.append(ev)
                        self.last_alert_ts = max(self.last_alert_ts, ev.timestamp)
            if now >= self._next_device:
                # With the frame tap active, beacons are parsed directly; Kismet's AP
                # records would only duplicate them.
                self._next_device = now + self.cfg.poll_interval * (5 if self.frame_tap else 1)
                records = self.client.devices_since(self.last_device_ts)
                self.last_device_ts = now + self.offset
                for rec in records:
                    ev = device_to_event(rec, self.sensor_name, now + self.offset)
                    if ev:
                        out.append(ev)
            if now >= self._next_ds:
                self._next_ds = now + self.cfg.datasource_check_interval
                self._refresh_datasources()
                if self.cfg.frame_tap and self.frame_tap_factory and self.frame_tap is None:
                    self._open_frame_tap()
            self._healthy = True
        except KismetError as exc:
            self._healthy = False
            raise BackendUnavailable(str(exc)) from exc
        if self.frame_tap is not None:
            try:
                out.extend(self.frame_tap.poll(timeout if not out else 0.0))
            except BackendUnavailable as exc:
                self.frame_tap_error = str(exc)
                self.frame_tap.close()
                self.frame_tap = None
        elif not out:
            wait = min(timeout, max(0.0, min(self._next_alert, self._next_device) - self.clock()))
            if wait > 0:
                self.sleep(wait)
        self.stats["events"] += len(out)
        return out

    def set_interface(self, interface: str) -> None:
        self.sensor_interface = interface
        if self.frame_tap:
            self.frame_tap.close()
            self.frame_tap = None

    def status(self) -> BackendStatus:
        ds = sensor_datasource(self.datasources, self.sensor_interface)
        sensor_ok = None if ds is None else (ds.running and not ds.error)
        detail = f"Kismet {self.version or '?'}"
        if ds is None:
            detail += f"; no datasource for {self.sensor_interface}"
        elif not sensor_ok:
            detail += f"; datasource {ds.name} not running: {ds.error_reason or 'unknown'}"
        return BackendStatus(
            self.name, self._healthy, detail, sensor_ok=sensor_ok,
            extra={
                "eventbus": bool(self.eventbus and self.eventbus.connected.is_set()),
                "frame_tap": self.frame_tap is not None,
                "frame_tap_error": self.frame_tap_error,
                "datasource": ds.__dict__ if ds else None,
            },
        )


# ---------------------------------------------------------------------------
# `kismet check` / `kismet config`
# ---------------------------------------------------------------------------


def check_kismet(client: KismetClient, cfg: Config) -> list[tuple[str, str, str]]:
    """Return [(level, name, message)] describing Kismet readiness. Read-only."""
    out: list[tuple[str, str, str]] = []
    try:
        status = client.system_status()
    except KismetAuthError as exc:
        return [("fail", "auth", str(exc))]
    except KismetUnavailable as exc:
        return [("fail", "reachable", f"{exc} -- install/start Kismet or use backend.type: passive")]
    except KismetError as exc:
        return [("fail", "reachable", str(exc))]
    out.append(("ok", "reachable", f"Kismet {status.get('kismet.system.version', '?')} at {client.base}"))
    parts = urllib.parse.urlsplit(client.base)
    if parts.scheme == "http" and client.auth_headers() and not is_loopback_host(parts.hostname or ""):
        out.append(("warn", "transport", "credentials are sent unencrypted over http to a non-loopback "
                                         "host; use https, or run Kismet on this machine"))

    try:
        sources = [DatasourceInfo.from_record(r) for r in client.datasources()]
        ds = sensor_datasource(sources, cfg.sensor.interface)
        if ds is None:
            out.append(("warn", "datasource",
                        f"no Kismet datasource for {cfg.sensor.interface}; add "
                        f"'source={cfg.sensor.interface}:name=daybreak' (see `daybreak-wids kismet config`)"))
        elif ds.running and not ds.error:
            mode = "hopping" if ds.hopping else f"locked to {ds.channel}"
            out.append(("ok", "datasource", f"{ds.name} on {ds.capture_interface or ds.interface} running ({mode})"))
        else:
            out.append(("fail", "datasource", f"{ds.name} not running: {ds.error_reason or 'unknown error'}"))
        for other in sources:
            if other.matches("wlo1") or any(other.matches(p) for p in cfg.sensor.protected_interfaces):
                out.append(("fail", "datasource",
                            f"Kismet datasource {other.name} uses protected interface {other.interface}; "
                            "remove it from the Kismet configuration"))
    except KismetError as exc:
        out.append(("warn", "datasource", f"cannot list datasources: {exc}"))

    try:
        defined = {str(d.get("kismet.alert.definition.header")) for d in client.alert_definitions()}
        for header in REQUESTED_WIDS_ALERTS:
            if header in defined:
                out.append(("ok", f"alert:{header}", "available"))
            else:
                out.append(("warn", f"alert:{header}", "not defined by this Kismet version "
                            "(daybreak-wids' own detectors cover it)"))
        if "APSPOOF" in defined:
            out.append(("info", "alert:APSPOOF", "requires apspoof= lines with your authorized BSSIDs "
                        "(see `daybreak-wids kismet config`)"))
    except KismetError as exc:
        out.append(("warn", "alerts", f"cannot read alert definitions: {exc}"))

    try:
        packet_logs = [r for r in client.active_logs() if _is_packet_log(r)]
        if packet_logs:
            out.append(("warn", "logging", "Kismet is writing packet logs (these can contain WPA "
                        "handshakes); daybreak-wids keeps metadata only -- consider enable_logging=false"))
        else:
            out.append(("ok", "logging", "no Kismet packet logs active"))
    except KismetError:
        out.append(("info", "logging", "cannot query Kismet logging state"))
    return out


_PACKET_LOG_CLASSES = {"kismet", "pcapng", "pcapppi", "pcap"}


def _find_key(obj: Any, key: str, depth: int = 0) -> Any:
    if isinstance(obj, Mapping):
        if key in obj:
            return obj[key]
        if depth < 3:
            for v in obj.values():
                found = _find_key(v, key, depth + 1)
                if found is not None:
                    return found
    return None


def _is_packet_log(record: Any) -> bool:
    """True for an open Kismet log that stores packets (kismetdb / pcap / pcapng)."""
    if not isinstance(record, Mapping) or record.get("kismet.logfile.open") is False:
        return False
    cls = str(_find_key(record, "kismet.logfile.type.class") or "").lower()
    path = str(record.get("kismet.logfile.path", "")).lower()
    return cls in _PACKET_LOG_CLASSES or path.endswith((".kismet", ".pcapng", ".pcapppi", ".pcap"))


def kismet_site_conf(cfg: Config) -> str:
    """Suggested ``kismet_site.conf`` snippet (printed for the operator; never written)."""
    lines = [
        "# Suggested by daybreak-wids -- review, then add to /etc/kismet/kismet_site.conf",
        "# Sensor: dedicated adapter only. Never add the internet interface "
        f"({', '.join(cfg.sensor.protected_interfaces) or 'none'}).",
    ]
    channels = cfg.sensor.channels or sorted({c for n in cfg.protected_networks for c in n.channels})
    src = f"source={cfg.sensor.interface}:name=daybreak"
    if len(channels) == 1:
        src += f",channel={channels[0]}"
    elif channels:
        src += f",channels=\"{','.join(str(c) for c in channels)}\""
    lines.append(src)
    lines.append("")
    lines.append("# Kismet APSPOOF: authorized BSSIDs per protected SSID")
    for net in cfg.protected_networks:
        if not net.bssids:
            lines.append(f"# {net.name}: unconfigured (no BSSIDs) -- no apspoof rule generated")
            continue
        if any(ch in net.ssid for ch in '"\\'):
            lines.append(f"# {net.name}: SSID contains quotes/backslashes -- write this rule by hand")
            continue
        safe_name = re.sub(r"[^A-Za-z0-9_]", "_", net.name)
        lines.append(f'apspoof={safe_name}:ssid="{net.ssid}",validmacs="{",".join(net.bssids)}"')
    lines += [
        "",
        "# daybreak-wids stores metadata only. Kismet's own logs can contain full frames,",
        "# including WPA handshakes. Disable them unless you need them for other purposes:",
        "enable_logging=false",
    ]
    return "\n".join(lines) + "\n"
