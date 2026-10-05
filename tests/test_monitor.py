import socket

from conftest import HOME_BSSID, make_config
from daybreak.models import Event
from daybreak.monitor import MonitorRunner, read_status, status_path
from daybreak.runtime import build_runtime
from daybreak.safety import InterfaceGuard
from daybreak.sensor.backend import Backend, BackendStatus, BackendUnavailable
from daybreak.sensor.kismet import KismetBackend
from daybreak.sensor.passive import PassiveBackend
from daybreak.sensor.select import choose_backend, listen_channels
from daybreak.sensor.status import SensorHealthMonitor
from helpers import host_runner, host_sysfs

ALFA = "wlx00c0cab85c32"
T0 = 1790000000.0


class FakeClock:
    def __init__(self, start=1000.0, step=0.5):
        self.start = self.now = start
        self.step = step
        self.scheduled = []  # (elapsed seconds, callable)

    def at(self, elapsed, fn):
        self.scheduled.append((elapsed, fn))

    def __call__(self):
        self.now += self.step
        for item in [x for x in self.scheduled if self.now - self.start >= x[0]]:
            self.scheduled.remove(item)
            item[1]()
        return self.now


class FakeBackend(Backend):
    name = "passive"

    def __init__(self, batches, fail_open=0, sensor_ok=True):
        super().__init__(ALFA)
        self.batches = list(batches)
        self.fail_open = fail_open
        self.opened = 0
        self.closed = 0
        self.sensor_ok = sensor_ok

    def open(self):
        if self.fail_open > 0:
            self.fail_open -= 1
            raise BackendUnavailable("device busy")
        self.opened += 1

    def close(self):
        self.closed += 1

    def poll(self, timeout):
        if not self.batches:
            return []
        b = self.batches.pop(0)
        if isinstance(b, Exception):
            raise b
        if callable(b):
            return b() or []
        return b

    def status(self):
        return BackendStatus(self.name, True, "fake", sensor_ok=self.sensor_ok)


def deauths(n, start=0.0):
    return [Event.from_dict({"ts": T0 + start + i * 0.1, "type": "deauth", "bssid": HOME_BSSID,
                             "src": HOME_BSSID, "dst": f"10:22:33:44:55:0{i % 4}", "reason": 7})
            for i in range(n)]


def runtime(tmp_path, **cfg):
    config = make_config(tmp_path, sensor={"health_check_interval": 1.0, **cfg.pop("sensor", {})}, **cfg)
    return build_runtime(config)


def test_runner_processes_events_and_writes_status(tmp_path):
    rt = runtime(tmp_path)
    backend = FakeBackend([deauths(15)])
    summary = MonitorRunner(rt, backend, duration=5, clock=FakeClock(), sleep=lambda s: None).run()
    assert summary["stats"]["processed"] == 15
    assert rt.db.list_alerts(alert_type="DEAUTH_BURST")
    st = read_status(status_path(rt))
    assert st["state"] == "stopped" and st["stats"]["processed"] == 15 and st["alive"] is False
    assert (rt.config.log_dir / "daybreak.log").exists() and (rt.config.log_dir / "alerts.jsonl").exists()


def test_sensor_disconnect_and_reconnect(tmp_path):
    fs, _ = host_sysfs(tmp_path)
    rt = runtime(tmp_path)
    health = SensorHealthMonitor(ALFA, sysfs_root=fs.net)
    recovered = []

    clock = FakeClock(step=0.5)
    clock.at(5, lambda: fs.remove(ALFA))  # USB unplug / driver reset
    clock.at(15, lambda: fs.add_wireless(ALFA, phy="phy4", mac="00:c0:ca:b8:5c:32", driver="mt7921u",
                                         usb_id="0e8d:7961"))
    backend = FakeBackend([deauths(2)] + [[]] * 8 + [BackendUnavailable("sensor went away")]
                          + [[]] * 10 + [deauths(2, start=60)])
    runner = MonitorRunner(rt, backend, health=health, duration=30, clock=clock,
                           sleep=lambda s: None, recover=lambda iface: recovered.append(iface) or True)
    runner.run()
    kinds = [a.alert_type for a in rt.alerts.delivered]
    assert "SENSOR_LOST" in kinds and "SENSOR_RECOVERED" in kinds
    assert kinds.index("SENSOR_LOST") < kinds.index("SENSOR_RECOVERED")
    lost = next(a for a in rt.alerts.delivered if a.alert_type == "SENSOR_LOST")
    assert lost.severity.name == "MEDIUM" and "USB" in lost.summary
    statuses = [r["status"] for r in reversed(rt.db.latest_sensor_status(limit=20))]
    assert "LOST" in statuses and statuses.index("LOST") < len(statuses) - 1 - statuses[::-1].index("ONLINE")
    assert recovered == [ALFA]           # monitor mode restoration requested for the sensor only
    assert backend.opened >= 2            # passive monitoring resumed
    assert runner.rt.pipeline.stats["processed"] == 4


def test_backend_retry_with_backoff(tmp_path):
    rt = runtime(tmp_path)
    backend = FakeBackend([deauths(3)], fail_open=2)
    clock = FakeClock(step=1.0)
    MonitorRunner(rt, backend, duration=60, clock=clock, sleep=lambda s: None).run()
    assert backend.opened == 1
    rows = [r["status"] for r in rt.db.latest_sensor_status(limit=10)]
    assert "BACKEND_UNAVAILABLE" in rows and "BACKEND_RECOVERED" in rows
    assert rt.pipeline.stats["processed"] == 3


def test_kismet_datasource_failure_reported_as_sensor_lost(tmp_path):
    fs, _ = host_sysfs(tmp_path)
    rt = runtime(tmp_path)
    backend = FakeBackend([[], [], [], [], [], []], sensor_ok=True)
    backend.name = "kismet"
    health = SensorHealthMonitor(ALFA, sysfs_root=fs.net)

    def fail():
        backend.sensor_ok = False
        return []

    backend.batches = [[], fail, [], [], [], [], [], []]
    MonitorRunner(rt, backend, health=health, duration=10, clock=FakeClock(step=0.5), sleep=lambda s: None).run()
    lost = [a for a in rt.alerts.delivered if a.alert_type == "SENSOR_LOST"]
    assert lost and lost[0].details["reason"] == "fake"


def test_kismet_unavailable_falls_back_to_passive(tmp_path):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    cfg = make_config(tmp_path, backend={"type": "auto", "kismet": {"url": f"http://127.0.0.1:{port}",
                                                                    "timeout": 1}})
    messages = []
    fs, route = host_sysfs(tmp_path)
    guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=host_runner())
    backend = choose_backend(cfg, guard=guard, runner=host_runner(), log=messages.append)
    assert isinstance(backend, PassiveBackend) and backend.interface == ALFA
    assert backend.channels == [36, 6] == listen_channels(cfg)
    assert "Kismet unavailable" in messages[0]
    forced = choose_backend(cfg, "kismet", guard=guard, runner=host_runner(), log=messages.append)
    assert isinstance(forced, KismetBackend)  # explicit kismet: retried by the runner instead


def test_replay_and_pcap_backends_selected(tmp_path):
    cfg = make_config(tmp_path)
    assert choose_backend(cfg, replay=__file__).name == "replay"
    assert choose_backend(cfg, pcap=__file__).name == "pcap"


def test_passive_channel_hopping_is_guarded(tmp_path):
    fs, route = host_sysfs(tmp_path)
    runner = host_runner()
    guard = InterfaceGuard(["wlo1"], sysfs_root=fs.net, route_file=route, runner=runner)
    cfg = make_config(tmp_path, backend={"type": "passive", "passive": {"interface": "wlo1mon"}})
    fs.add_wireless("wlo1mon", phy="phy0", mac="02:00:00:00:00:01", driver="iwlwifi")
    backend = choose_backend(cfg, guard=guard, runner=runner)
    backend._tune(36)  # attempting to hop on a protected PHY is refused, never executed
    assert runner.executed == [] and "protected" in backend.errors[-1]


def test_live_monitor_enforces_retention_but_replay_does_not(tmp_path):
    rt = runtime(tmp_path, storage={"database": "var/test.db", "retention_days": 1})
    old = T0 - 3 * 86400
    rt.db.insert_events(deauths(3, start=-3 * 86400))
    rt.db.upsert_station(mac="10:22:33:44:55:01", bssid=HOME_BSSID, network_id=None, timestamp=old)

    class ReplayLike(FakeBackend):
        name = "replay"

    MonitorRunner(rt, ReplayLike([[]]), duration=2, clock=FakeClock(start=T0), sleep=lambda s: None).run()
    assert len(rt.db.query_events(until=T0 - 86400)) == 3      # offline analysis keeps old events
    messages = []
    MonitorRunner(rt, FakeBackend([[]]), duration=2, clock=FakeClock(start=T0), sleep=lambda s: None,
                  on_message=messages.append).run()
    assert rt.db.query_events(until=T0 - 86400) == [] and rt.db.list_stations() == []
    assert any(m.startswith("retention: removed 3 events") for m in messages)
    rt.close()
