"""Monitor loop: backend -> pipeline, with sensor health and backend retries."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .detectors.base import SENSOR_LOST, SENSOR_RECOVERED
from .models import iso_utc
from .pipeline import sensor_alert
from .runtime import Runtime
from .scoring import threat_level
from .sensor.backend import Backend, BackendUnavailable
from .sensor.status import HealthTransition, SensorHealthMonitor

log = logging.getLogger("daybreak.monitor")

STATUS_FILE = "monitor.status.json"


def status_path(runtime_or_config: Any) -> Path:
    cfg = getattr(runtime_or_config, "config", runtime_or_config)
    return cfg.state_dir / STATUS_FILE


def read_status(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    pid = data.get("pid")
    alive = False
    if isinstance(pid, int) and data.get("state") == "running":
        try:
            os.kill(pid, 0)
            alive = True
        except PermissionError:
            alive = True  # exists, owned by another user (e.g. root)
        except OSError:
            alive = False
    data["alive"] = alive
    return data


class MonitorRunner:
    def __init__(self, runtime: Runtime, backend: Backend, *, health: SensorHealthMonitor | None = None,
                 duration: float | None = None, write_status: bool = True,
                 recover: Callable[[str], bool] | None = None,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep,
                 stop: threading.Event | None = None, on_message: Callable[[str], None] | None = None):
        self.rt = runtime
        self.backend = backend
        self.health = health
        self.duration = duration
        self.write_status = write_status and not runtime.dry_run
        self.recover = recover
        self.clock = clock
        self.sleep = sleep
        self.stop = stop or threading.Event()
        self.say = on_message or (lambda msg: log.info(msg))
        self.cfg = runtime.config
        self.backend_open = False
        self.backend_failures = 0
        self.next_open = 0.0
        self.last_backend_error: str | None = None
        self.sensor_online: bool | None = None
        self.next_health = 0.0
        self.next_status = 0.0
        self.started = 0.0

    # -- status ------------------------------------------------------------------
    def _record(self, status: str, details: dict[str, Any] | None = None) -> None:
        if self.rt.db is not None:
            self.rt.db.record_sensor_status(sensor=self.cfg.sensor.interface,
                                            interface=self.health.interface if self.health else None,
                                            status=status, backend=self.backend.name, details=details or {},
                                            timestamp=self.clock())

    def _status_doc(self, state: str) -> dict[str, Any]:
        p = self.rt.pipeline
        recent = [a for a in self.rt.alerts.delivered if a.timestamp >= (p.last_event_ts or 0) - 300]
        try:
            bstatus = self.backend.status()
            backend = {"name": bstatus.name, "healthy": bstatus.healthy and self.backend_open,
                       "detail": bstatus.detail, "extra": bstatus.extra}
        except Exception as exc:  # status must never crash the loop
            backend = {"name": self.backend.name, "healthy": False, "detail": str(exc)}
        return {
            "state": state, "pid": os.getpid(), "started": self.started, "updated": self.clock(),
            "config": str(self.cfg.path) if self.cfg.path else None,
            "backend": backend, "backend_error": self.last_backend_error,
            "sensor": {"interface": self.health.interface if self.health else self.cfg.sensor.interface,
                       "online": self.sensor_online},
            "stats": dict(p.stats), "events_by_type": dict(p.type_counts),
            "alerts": dict(self.rt.alerts.stats),
            "last_event": iso_utc(p.last_event_ts) if p.last_event_ts else None,
            "threat_level": threat_level(recent),
        }

    def _write_status(self, state: str) -> None:
        if not self.write_status:
            return
        path = status_path(self.rt)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._status_doc(state), indent=2, default=str), encoding="utf-8")
        tmp.replace(path)

    # -- sensor health ---------------------------------------------------------------
    def _transition(self, t: HealthTransition, reason: str | None = None) -> None:
        details = dict(t.details)
        if reason:
            details["reason"] = reason
        if t.status == SENSOR_LOST:
            self.sensor_online = False
            self.say(f"SENSOR_LOST {t.interface}: {reason or 'interface disappeared'}")
            self._record("LOST", details)
            if self.backend.name == "passive" and self.backend_open:
                self.backend.close()
                self.backend_open = False
        else:
            self.sensor_online = True
            self.say(f"SENSOR_RECOVERED {t.interface}")
            self._record("ONLINE", details)
            if t.previous_interface and t.previous_interface != t.interface:
                self.backend.set_interface(t.interface)
            if self.backend.name == "passive":
                if self.recover is not None:
                    ok = self.recover(t.interface)
                    details["monitor_mode_restored"] = ok
                self.backend_open = False
                self.next_open = 0.0
        alert = sensor_alert(t.status, t.timestamp, sensor=self.cfg.sensor.interface, interface=t.interface,
                             details=details, weight=self.cfg.scoring.weight("sensor_lost"))
        self.rt.pipeline.emit_external(alert)

    def _check_health(self, now: float) -> None:
        if self.health is None:
            return
        t = self.health.check(now)
        if t is not None:
            self._transition(t)
            return
        # Kismet can report its datasource failing while the interface still exists.
        if self.backend_open and self.backend.name == "kismet":
            st = self.backend.status()
            if st.sensor_ok is False and self.sensor_online:
                self._transition(HealthTransition(SENSOR_LOST, now, self.health.interface,
                                                  self.health.expected_mac), reason=st.detail)
            elif st.sensor_ok and self.sensor_online is False and self.health.state.value == "ONLINE":
                self._transition(HealthTransition(SENSOR_RECOVERED, now, self.health.interface,
                                                  self.health.expected_mac), reason=st.detail)
        if self.sensor_online is None and self.health.state.value == "ONLINE":
            self.sensor_online = True
            self._record("ONLINE", {"startup": True})

    # -- backend --------------------------------------------------------------------------
    def _try_open(self, now: float) -> None:
        if now < self.next_open:
            return
        if self.sensor_online is False and self.backend.name == "passive":
            return  # wait for the adapter to come back
        try:
            self.backend.open()
        except BackendUnavailable as exc:
            self.backend_failures += 1
            delay = min(30.0, 2.0 ** min(self.backend_failures, 5))
            self.next_open = now + delay
            if str(exc) != self.last_backend_error:
                self.say(f"backend {self.backend.name} unavailable: {exc} (retrying)")
                self._record("BACKEND_UNAVAILABLE", {"error": str(exc)})
            self.last_backend_error = str(exc)
            if self.backend.name in ("replay", "pcap"):
                raise
            return
        if self.backend_failures or self.last_backend_error:
            self._record("BACKEND_RECOVERED", {"after_failures": self.backend_failures})
        self.backend_open = True
        self.backend_failures = 0
        self.last_backend_error = None
        self.say(f"backend {self.backend.name} open: {self.backend.status().detail}")

    # -- main loop ---------------------------------------------------------------------------
    def run(self) -> dict[str, Any]:
        self.started = self.clock()
        self._write_status("running")
        try:
            while not self.stop.is_set():
                now = self.clock()
                if self.duration is not None and now - self.started >= self.duration:
                    break
                if now >= self.next_health:
                    self._check_health(now)
                    self.next_health = now + self.cfg.sensor.health_check_interval
                if not self.backend_open:
                    self._try_open(now)
                    if not self.backend_open:
                        self.sleep(0.5)
                        continue
                try:
                    events = self.backend.poll(0.5)
                except BackendUnavailable as exc:
                    self.backend_open = False
                    self.backend.close()
                    self.last_backend_error = str(exc)
                    self.say(f"backend {self.backend.name} lost: {exc}")
                    self._record("BACKEND_UNAVAILABLE", {"error": str(exc)})
                    self.next_open = now + 2.0
                    self.next_health = 0.0  # check the sensor right away
                    continue
                for ev in events:
                    self.rt.pipeline.process(ev)
                if self.backend.finished:
                    break
                if now >= self.next_status:
                    self.rt.pipeline.flush()
                    self._write_status("running")
                    self.next_status = now + 5.0
        finally:
            self.rt.pipeline.flush()
            if self.backend_open:
                self.backend.close()
            self._write_status("stopped")
        return self._status_doc("stopped")
