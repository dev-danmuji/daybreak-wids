"""A tiny fake Kismet REST server on 127.0.0.1 for integration tests."""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API_KEY = "test-readonly-key"
NOW = 1790000000.0


def alert(header, ts, bssid="AA:BB:CC:DD:EE:FF", source="AA:BB:CC:DD:EE:FF",
          dest="FF:FF:FF:FF:FF:FF", channel="36", text="", hash_=None):
    return {
        "kismet.alert.header": header,
        "kismet.alert.timestamp": ts,
        "kismet.alert.transmitter_mac": bssid,
        "kismet.alert.source_mac": source,
        "kismet.alert.dest_mac": dest,
        "kismet.alert.other_mac": "00:00:00:00:00:00",
        "kismet.alert.channel": channel,
        "kismet.alert.frequency": 5180000,
        "kismet.alert.text": text or f"{header} test alert",
        "kismet.alert.class": "DENIAL",
        "kismet.alert.severity": 10,
        "kismet.alert.hash": hash_ if hash_ is not None else hash((header, ts)) & 0xFFFFFFFF,
    }


class FakeKismetState:
    def __init__(self):
        self.version = "2025-09-R1"
        self.alerts = []
        self.devices = []
        self.definitions = ["DEAUTHFLOOD", "BCASTDISCON", "DISCONCODEINVALID", "APSPOOF",
                            "ADVCRYPTCHANGE", "CRYPTODROP", "CHANCHANGE", "NOCLIENTMFP"]
        self.datasources = [{
            "kismet.datasource.uuid": "5FE308BD-0000-0000-0000-00C0CAB85C32",
            "kismet.datasource.name": "daybreak",
            "kismet.datasource.interface": "wlx00c0cab85c32",
            "kismet.datasource.capture_interface": "wlx00c0cab85c32mon",
            "kismet.datasource.running": 1,
            "kismet.datasource.error": 0,
            "kismet.datasource.error_reason": "",
            "kismet.datasource.channel": "36",
            "kismet.datasource.hopping": 0,
            "kismet.datasource.num_packets": 1234,
        }]
        self.logs = []
        self.requests = []
        self.device_fields_requested = []
        self.leak_extra_fields = False


def make_handler(state: FakeKismetState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence
            pass

        def _send(self, code, payload):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self):
            return f"KISMET={API_KEY}" in (self.headers.get("Cookie") or "")

        def _route(self, body=None):
            state.requests.append((self.command, self.path))
            if not self._authorized():
                return self._send(401, {"error": "login required"})
            path = urllib.parse.urlsplit(self.path).path
            if path == "/system/status.json":
                return self._send(200, {"kismet.system.version": state.version,
                                        "kismet.system.timestamp.sec": int(NOW),
                                        "kismet.system.timestamp.usec": 0})
            if path == "/datasource/all_sources.json":
                return self._send(200, state.datasources)
            if path == "/alerts/definitions.json":
                return self._send(200, [{"kismet.alert.definition.header": h} for h in state.definitions])
            if path.startswith("/alerts/wrapped/last-time/"):
                ts = float(path.split("/")[4])
                items = [a for a in state.alerts if a["kismet.alert.timestamp"] > ts]
                return self._send(200, {"kismet.alert.list": items, "kismet.alert.timestamp": NOW + 100})
            if path.startswith("/devices/last-time/"):
                params = urllib.parse.parse_qs(body or "")
                fields = json.loads(params.get("json", ["{}"])[0]).get("fields", [])
                state.device_fields_requested.append(fields)
                out = []
                for d in state.devices:
                    rec = dict(d)
                    if state.leak_extra_fields:
                        rec["dot11.device.wpa_handshake_list"] = [{"dot11.eapol.nonce": "AA" * 32}]
                    out.append(rec)
                return self._send(200, out)
            if path == "/logging/active.json":
                return self._send(200, state.logs)
            return self._send(404, {"error": "not found"})

        def do_GET(self):
            self._route()

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            self._route(self.rfile.read(length).decode())

    return Handler


class FakeKismet:
    def __init__(self):
        self.state = FakeKismetState()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.state))
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02},
                                       daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
