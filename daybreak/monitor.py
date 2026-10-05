"""Monitor loop: backend -> pipeline, with sensor health and backend retries."""

from __future__ import annotations

import contextlib
import glob
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .detectors.base import SENSOR_LOST, SENSOR_RECOVERED
from .fileperm import write_private_atomic
from .models import iso_utc
from .pipeline import protected_alert, sensor_alert
from .runtime import Runtime
from .scoring import threat_level
from .sensor.backend import Backend, BackendUnavailable
from .sensor.status import HealthTransition, SensorHealthMonitor

log = logging.getLogger("daybreak.monitor")

OFFLINE_BACKENDS = {"replay", "pcap"}
PRUNE_INTERVAL = 3600.0  # seconds between retention passes
PROTECTED_CHECK_INTERVAL = 10.0  # seconds between protected-interface verifications

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
                 stop: threading.Event | None = None, on_message: Callable[[str], None] | None = None,
                 guard: Any = None):
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
        self.next_prune = 0.0
        self.started = 0.0
        # Live runs: protected interfaces are verified continuously, not only around commands.
        self.guard = guard
        self.protected_before: dict[str, Any] | None = None
        self.protected_changes: dict[str, list[str]] = {}
        self.next_protected = 0.0
        self._suspended_recover: Callable[[str], bool] | None = None

    # -- retention ---------------------------------------------------------------
    def _prune(self, now: float) -> None:
        """storage.retention_days, enforced by the live monitor (never during a replay or pcap
        analysis, whose events may legitimately be older than the retention period)."""
        days = self.cfg.storage.retention_days
        if self.rt.db is None or days <= 0 or self.backend.name in OFFLINE_BACKENDS:
            return
        cutoff = now - days * 86400
        removed = self.rt.db.prune(older_than=cutoff)
        removed["rotated log files"] = self._prune_rotated_logs(cutoff)
        if any(removed.values()):
            self.say("retention: removed " + ", ".join(f"{n} {t}" for t, n in removed.items() if n)
                     + f" older than {days} days")

    def _prune_rotated_logs(self, cutoff: float) -> int:
        """Rotated backups (``daybreak.log.N``, ``alerts.jsonl.N``) last written before ``cutoff``.
        The active files are size-rotated and may hold older lines until they rotate."""
        count = 0
        log_dir = self.cfg.log_dir
        for name in (self.cfg.logging.human_log, self.cfg.logging.jsonl_log):
            for old in log_dir.glob(glob.escape(name) + ".*"):
                if not old.name[len(name) + 1:].isdigit() or old.is_symlink() or not old.is_file():
                    continue
                if old.stat().st_mtime < cutoff:
                    with contextlib.suppress(OSError):
                        old.unlink()
                        count += 1
        return count

    # -- protected interfaces -----------------------------------------------------
    def _check_protected(self, now: float) -> None:
        if self.guard is None or self.protected_before is None:
            return
        changes = self.guard.verify_unchanged(self.protected_before, self.guard.snapshot_protected())
        if changes == self.protected_changes:
            return
        self.protected_changes = changes
        if not changes:
            self.say("protected interfaces are back to their state at start")
            self._record("PROTECTED_RESTORED", {})
            if self._suspended_recover is not None:  # re-preparing the sensor is safe again
                self.recover, self._suspended_recover = self._suspended_recover, None
                self.say("auto_prepare re-enabled")
            return
        self._protected_alert(now, changes)

    def _protected_alert(self, now: float, changes: dict[str, list[str]]) -> None:
        detail = "; ".join(f"{name}: {', '.join(diff)}" for name, diff in sorted(changes.items()))
        if self.recover is not None:  # no sensor re-preparation while a protected interface differs
            self._suspended_recover, self.recover = self.recover, None
        self.say(f"PROTECTED_INTERFACE_CHANGED {detail} (daybreak-wids sends no commands to protected "
                 "interfaces); auto_prepare suspended until it is back to its state at start")
        self._record("PROTECTED_CHANGED", {"changes": changes})
        self.rt.pipeline.emit_external(protected_alert(
            now, changes, sensor=self.cfg.sensor.interface,
            weight=self.cfg.scoring.weight("protected_interface_changed")))

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
        # mkstemp + rename: a planted symlink cannot redirect the write (see fileperm)
        write_private_atomic(status_path(self.rt), json.dumps(self._status_doc(state), indent=2, default=str))

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
                    recover = self.recover
                    ok = recover(t.interface)
                    details["monitor_mode_restored"] = ok
                    changed = getattr(recover, "last_protected_changes", None)
                    if changed:  # seen by the recovery's own before/after check
                        recover.last_protected_changes = None
                        self._protected_alert(t.timestamp, changed)
                self.backend_open = False
                self.next_open = 0.0
        alert = sensor_alert(t.status, t.timestamp, sensor=self.cfg.sensor.interface, interface=t.interface,
                             details=details, weight=self.cfg.scoring.weight("sensor_lost"))
        self.rt.pipeline.emit_external(alert)

    def _check_health(self, now: float) -> None:
        if self.health is None:
            return
        tracked = self.health.interface
        t = self.health.check(now)
        if t is not None:
            self._transition(t)
            return
        if self.health.interface != tracked:
            self.say(f"sensor adapter {self.health.expected_mac} is now tracked as {self.health.interface} "
                     f"(was {tracked})")
            if self.backend.name == "passive":
                self.backend.set_interface(self.health.interface)
                self.backend_open = False
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
        if self.guard is not None:
            self.protected_before = self.guard.snapshot_protected()
        self._write_status("running")
        try:
            while not self.stop.is_set():
                now = self.clock()
                if self.duration is not None and now - self.started >= self.duration:
                    break
                if now >= self.next_health:
                    self._check_health(now)
                    self.next_health = now + self.cfg.sensor.health_check_interval
                if now >= self.next_prune:
                    self._prune(now)
                    self.next_prune = now + PRUNE_INTERVAL
                if self.guard is not None and now >= self.next_protected:
                    self._check_protected(now)
                    self.next_protected = now + PROTECTED_CHECK_INTERVAL
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
