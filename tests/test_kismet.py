import json
import queue
import socket
import time

import pytest

from daybreak.config import KismetConfig
from daybreak.models import EventType
from daybreak.sensor.backend import BackendUnavailable
from daybreak.sensor.kismet import (
    ENDPOINTS, SAFE_DEVICE_FIELDS, EventbusReader, KismetAuthError, KismetBackend, KismetClient,
    KismetError, KismetUnavailable, alert_to_event, check_kismet, device_to_event, eventbus_url,
    kismet_security, kismet_site_conf,
)
from kismet_fake import API_KEY, NOW, FakeKismet, alert

ALFA = "wlx00c0cab85c32"


@pytest.fixture
def kismet():
    with FakeKismet() as fk:
        yield fk


def client_for(fk, key=API_KEY):
    return KismetClient(fk.url, api_key=key, timeout=2)


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# -- client ----------------------------------------------------------------------------------------

def test_status_and_server_time(kismet):
    c = client_for(kismet)
    st = c.system_status()
    assert st["kismet.system.version"] == "2025-09-R1"
    assert c.server_time(st) == NOW


def test_auth_error(kismet):
    with pytest.raises(KismetAuthError, match="read-only API key"):
        client_for(kismet, key="wrong").system_status()


def test_kismet_api_unavailable():
    c = KismetClient(f"http://127.0.0.1:{free_port()}", api_key="x", timeout=1)
    with pytest.raises(KismetUnavailable, match="not reachable"):
        c.system_status()
    backend = KismetBackend(KismetConfig(url=c.base, use_eventbus=False, frame_tap=False),
                            sensor_interface=ALFA, client=c)
    with pytest.raises(BackendUnavailable):
        backend.open()


def test_only_allow_listed_read_only_endpoints(kismet):
    c = client_for(kismet)
    for path in ("/datasource/add_source.cmd", "/phy/phy80211/handshake/AA:BB/handshake.pcap",
                 "/datasource/by-uuid/x/set_channel.cmd", "/pcap/all_packets.pcapng"):
        with pytest.raises(KismetError, match="not allow-listed"):
            c.request(path)
    assert not any(p.endswith(".cmd") for p in ENDPOINTS.values())


def test_device_fields_never_request_key_material(kismet):
    forbidden = ("handshake", "pmkid", "nonce", "eapol", "packet", "key", "anonce")
    for path, _name in SAFE_DEVICE_FIELDS:
        assert not any(word in path.lower() for word in forbidden), path
    kismet.state.devices = [{"mac": "AA:BB:CC:DD:EE:FF", "ssid": "ExampleSSID", "type": "Wi-Fi AP",
                             "crypt_string": "WPA2-PSK AES-CCMP"}]
    kismet.state.leak_extra_fields = True  # a server ignoring simplification
    records = client_for(kismet).devices_since(NOW - 60)
    assert records and "dot11.device.wpa_handshake_list" not in records[0]
    sent = kismet.state.device_fields_requested[-1]
    assert sent == [list(f) for f in SAFE_DEVICE_FIELDS]


# -- conversions ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("crypt,req,sup,mode,pmf", [
    ("Open", False, False, "OPEN", "disabled"),
    ("WEP104", False, False, "WEP", "disabled"),
    ("WPA2 WPA2-PSK AES-CCMP", False, False, "WPA2-PSK", "disabled"),
    ("WPA2-PSK AES-CCMP", False, True, "WPA2-PSK", "capable"),
    ("WPA3 WPA3-PSK WPA3-SAE AES-CCMP", False, True, "WPA2/WPA3-TRANSITION", "capable"),
    ("WPA3-SAE AES-CCMP", True, True, "WPA3-SAE", "required"),
    ("WPA1-PSK TKIP", False, False, "WPA", "disabled"),
    ("WPA2-EAP AES-CCMP", False, True, "WPA2-ENTERPRISE", "capable"),
])
def test_kismet_crypt_string(crypt, req, sup, mode, pmf):
    prof = kismet_security(crypt, req, sup)
    assert prof.mode == mode and prof.pmf == pmf and prof.source == "kismet"


def test_alert_to_event():
    ev = alert_to_event(alert("DEAUTHFLOOD", NOW + 1, dest="FF:FF:FF:FF:FF:FF"), "alfa")
    assert ev.event_type is EventType.KISMET_ALERT
    assert ev.bssid == "AA:BB:CC:DD:EE:FF" and ev.channel == 36
    assert ev.metadata["kismet_header"] == "DEAUTHFLOOD" and ev.metadata["frequency"] == 5180
    assert alert_to_event({"kismet.alert.header": "X"}, "s") is None  # no timestamp
    assert alert_to_event("garbage", "s") is None


def test_device_to_event():
    ev = device_to_event({"mac": "aa:bb:cc:dd:ee:ff", "ssid": "ExampleSSID", "type": "Wi-Fi AP",
                          "crypt_string": "WPA3-SAE AES-CCMP", "mfp_required": 1, "mfp_supported": 1,
                          "ssid_channel": "36", "signal": -41, "num_clients": 3, "last_time": NOW},
                         "alfa", NOW)
    assert ev.event_type is EventType.BEACON and ev.ssid == "ExampleSSID"
    assert ev.security.mode == "WPA3-SAE" and ev.security.pmf == "required"
    assert ev.channel == 36 and ev.rssi == -41 and ev.metadata["num_clients"] == 3
    assert device_to_event({"mac": "aa:bb:cc:dd:ee:ff", "type": "Wi-Fi Client"}, "alfa", NOW) is None


# -- backend ----------------------------------------------------------------------------------------

def test_backend_polls_alerts_and_devices(kismet):
    kismet.state.alerts = [alert("DEAUTHFLOOD", NOW + 1), alert("BCASTDISCON", NOW + 2),
                           alert("OLDALERT", NOW - 50)]
    kismet.state.devices = [{"mac": "AA:BB:CC:DD:EE:FF", "ssid": "ExampleSSID", "type": "Wi-Fi AP",
                             "crypt_string": "WPA2-PSK AES-CCMP", "last_time": NOW}]
    cfg = KismetConfig(url=kismet.url, use_eventbus=False, frame_tap=False, poll_interval=0.01)
    b = KismetBackend(cfg, sensor_interface=ALFA, client=client_for(kismet), sleep=lambda s: None)
    b.open()
    events = b.poll(0.1)
    headers = [e.metadata.get("kismet_header") for e in events if e.event_type is EventType.KISMET_ALERT]
    assert headers == ["DEAUTHFLOOD", "BCASTDISCON"]  # alerts from before start are not replayed
    assert any(e.event_type is EventType.BEACON for e in events)
    st = b.status()
    assert st.healthy and st.sensor_ok is True and "2025-09-R1" in st.detail
    # Next poll: no duplicate alerts
    time.sleep(0.02)
    assert not [e for e in b.poll(0.0) if e.event_type is EventType.KISMET_ALERT]
    b.close()


def test_backend_reports_datasource_failure(kismet):
    kismet.state.datasources[0]["kismet.datasource.running"] = 0
    kismet.state.datasources[0]["kismet.datasource.error"] = 1
    kismet.state.datasources[0]["kismet.datasource.error_reason"] = "Interface went away"
    cfg = KismetConfig(url=kismet.url, use_eventbus=False, frame_tap=False)
    b = KismetBackend(cfg, sensor_interface=ALFA, client=client_for(kismet), sleep=lambda s: None)
    b.open()
    st = b.status()
    assert st.sensor_ok is False and "Interface went away" in st.detail


def test_backend_becomes_unavailable_mid_run(kismet):
    cfg = KismetConfig(url=kismet.url, use_eventbus=False, frame_tap=False, poll_interval=0.01)
    b = KismetBackend(cfg, sensor_interface=ALFA, client=client_for(kismet), sleep=lambda s: None)
    b.open()
    b.poll(0)
    kismet.server.shutdown()
    kismet.server.server_close()
    time.sleep(0.05)
    with pytest.raises(BackendUnavailable):
        for _ in range(3):
            time.sleep(0.02)
            b.poll(0)
    assert not b.status().healthy


class FakeWS:
    def __init__(self, messages):
        self.sent = []
        self.messages = list(messages)

    def send(self, data):
        self.sent.append(json.loads(data))

    def recv(self):
        if self.messages:
            return self.messages.pop(0)
        time.sleep(0.05)
        return ""

    def close(self):
        pass


def test_eventbus_subscribes_and_queues():
    ws = FakeWS([json.dumps({"ALERT": alert("APSPOOF", NOW + 5)}), "not json",
                 json.dumps({"DATASOURCE_ERROR": "uuid"})])
    q = queue.Queue()
    reader = EventbusReader("ws://127.0.0.1:1/eventbus/events.ws", q, connect=lambda url: ws,
                            reconnect_delay=10)
    reader.start()
    first = q.get(timeout=2)
    second = q.get(timeout=2)
    reader.stop()
    assert {"SUBSCRIBE": "ALERT"} in ws.sent and {"SUBSCRIBE": "DATASOURCE_ERROR"} in ws.sent
    assert "ALERT" in first and "DATASOURCE_ERROR" in second


def test_backend_uses_eventbus_alerts(kismet):
    ws = FakeWS([json.dumps({"ALERT": alert("CRYPTODROP", NOW + 3)})])
    cfg = KismetConfig(url=kismet.url, use_eventbus=True, frame_tap=False, poll_interval=60)
    b = KismetBackend(cfg, sensor_interface=ALFA, client=client_for(kismet), sleep=lambda s: None,
                      eventbus_connect=lambda url: ws)
    b.open()
    deadline = time.time() + 2
    found = []
    while time.time() < deadline and not found:
        found = [e for e in b.poll(0) if e.metadata.get("kismet_header") == "CRYPTODROP"]
        time.sleep(0.02)
    b.close()
    assert found


def test_eventbus_url_carries_no_credentials():
    assert eventbus_url("http://127.0.0.1:2501") == "ws://127.0.0.1:2501/eventbus/events.ws"
    assert eventbus_url("https://h:2501/kismet/") == "wss://h:2501/kismet/eventbus/events.ws"
    assert KismetClient("http://x", api_key="k").auth_headers() == {"Cookie": "KISMET=k"}
    assert KismetClient("http://x", username="u", password="p").auth_headers() == {"Authorization": "Basic dTpw"}


def test_eventbus_sends_credentials_as_headers_without_proxy(monkeypatch):
    websocket = pytest.importorskip("websocket")
    seen = {}

    def fake_create_connection(url, **kw):
        seen.update(url=url, **kw)
        raise ConnectionError("stop")

    monkeypatch.setattr(websocket, "create_connection", fake_create_connection)
    reader = EventbusReader(eventbus_url("http://127.0.0.1:2501"), queue.Queue(), headers={"Cookie": "KISMET=k"})
    with pytest.raises(ConnectionError):
        reader._open()
    assert "KISMET" not in seen["url"] and seen["header"] == ["Cookie: KISMET=k"]
    assert seen["http_no_proxy"] == ["*"]


def test_client_refuses_redirects(kismet):
    kismet.state.redirect = f"{kismet.url}/elsewhere"  # would receive the API key cookie
    with pytest.raises(KismetError, match="HTTP 302"):
        client_for(kismet).system_status()
    assert kismet.state.redirect_hits == 0


# -- check / config ----------------------------------------------------------------------------------------

def test_check_kismet(kismet, config):
    kismet.state.logs = [{"kismet.logfile.path": "/var/log/kismet/Kismet-20261005.kismet",
                          "kismet.logfile.open": True}]
    results = {name: (level, msg) for level, name, msg in check_kismet(client_for(kismet), config)}
    assert results["reachable"][0] == "ok"
    assert results["datasource"][0] == "ok" and "wlx00c0cab85c32mon" in results["datasource"][1]
    assert results["alert:DEAUTHFLOOD"][0] == "ok"
    assert results["alert:DISASSOCTRAFFIC"][0] == "warn"  # not defined by this Kismet build
    assert results["logging"][0] == "warn"


def test_check_kismet_unavailable(config):
    c = KismetClient(f"http://127.0.0.1:{free_port()}", api_key="x", timeout=1)
    [(level, name, msg)] = check_kismet(c, config)
    assert level == "fail" and name == "reachable" and "passive" in msg


def test_check_flags_protected_interface_datasource(kismet, config):
    kismet.state.datasources.append({"kismet.datasource.name": "bad", "kismet.datasource.interface": "wlo1",
                                     "kismet.datasource.capture_interface": "wlo1mon",
                                     "kismet.datasource.running": 1})
    results = check_kismet(client_for(kismet), config)
    assert any(level == "fail" and "protected interface wlo1" in msg for level, _, msg in results)


def test_site_conf(config):
    text = kismet_site_conf(config)
    assert "source=wlx00c0cab85c32:name=daybreak" in text
    assert 'apspoof=home:ssid="ExampleSSID",validmacs="AA:BB:CC:DD:EE:FF,AA:BB:CC:DD:EE:F0"' in text
    assert "lab: unconfigured" in text and "enable_logging=false" in text
    assert "source=wlo1" not in text


def test_reopen_replaces_eventbus_reader(kismet):
    sockets = []

    def connect(url):
        ws = FakeWS([])
        sockets.append(ws)
        return ws

    cfg = KismetConfig(url=kismet.url, use_eventbus=True, frame_tap=False)
    b = KismetBackend(cfg, sensor_interface=ALFA, client=client_for(kismet), sleep=lambda s: None,
                      eventbus_connect=connect)
    b.open()
    first = b.eventbus
    b.open()  # e.g. after Kismet restarted
    assert b.eventbus is not first and first._stop.is_set()
    b.close()
