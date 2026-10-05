"""daybreak-wids command line interface.

Authorized defensive monitoring only. No command transmits frames.
"""

from __future__ import annotations

import functools
import json
import os
import re
import signal
import sqlite3
import sys
import threading
import time
from datetime import datetime
from typing import Any, Callable

import click

from . import __version__
from .alerts.formatting import printable
from .config import ConfigError, load_config
from .fileperm import PRIVATE_UMASK
from .models import Severity, format_local
from .safety import CommandRunner, InterfaceGuard, SafetyViolation
from .sensor.control import sensor_identity_problem

BANNER = ("Authorized defensive monitoring only. daybreak-wids is passive: it never transmits, "
          "injects or deauthenticates.")


class App:
    def __init__(self, config_path: str | None, dry_run: bool, json_out: bool, verbose: int):
        self.config_path = config_path
        self.dry_run = dry_run
        self.json_out = json_out
        self.verbose = verbose
        self._config = None

    @property
    def config(self):
        if self._config is None:
            self._config = load_config(self.config_path)
        return self._config

    def reload(self):
        self._config = None
        return self.config

    def config_source(self) -> str:
        cfg = self.config
        return str(cfg.path) if cfg.path else f"built-in defaults (no config file; data in {cfg.base_dir})"

    def database(self, *, required: bool = True):
        from .storage import Database
        path = self.config.database_path
        if not path.exists() and not required:
            return None
        if not path.exists():
            raise click.ClickException(f"no database yet at {path} (run `daybreak-wids monitor start` first)")
        return Database(path)


def handle_errors(func: Callable) -> Callable:
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except SafetyViolation as exc:
            raise click.ClickException(f"safety: {exc}") from exc
        except (ConfigError, ValueError) as exc:
            raise click.ClickException(str(exc)) from exc
        except sqlite3.Error as exc:
            raise click.ClickException(f"database: {exc} (files written by a root-run monitor? see README: "
                                       "Data, logs and file locations)") from exc
    return wrapper


def emit_json(data: Any) -> None:
    click.echo(json.dumps(data, indent=2, default=str, ensure_ascii=False))


def parse_since(text: str | None, default: float | None = 86400.0) -> float | None:
    """'24h', '30m', '7d', '90s' or an ISO date/time -> epoch seconds."""
    if text is None:
        return None if default is None else time.time() - default
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhdw])\s*", text)
    if m:
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)]
        return time.time() - float(m.group(1)) * mult
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError as exc:
        raise click.BadParameter(f"cannot parse time {text!r} (use 24h, 30m, 7d or ISO-8601)") from exc


def table(rows: list[list[Any]], headers: list[str]) -> str:
    cells = [headers] + [["" if c is None else printable(c) for c in r] for r in rows]
    widths = [max(len(r[i]) for r in cells) for i in range(len(headers))]
    out = ["  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in cells]
    out.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(out)


LEVEL_MARK = {"ok": "ok  ", "info": "info", "warn": "WARN", "fail": "FAIL"}


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("-c", "--config", "config_path", type=click.Path(dir_okay=False), envvar="DAYBREAK_WIDS_CONFIG",
              help="Configuration file (default: ./config.yaml, ~/.config/daybreak-wids/config.yaml).")
@click.option("--dry-run", is_flag=True,
              help="Show what would happen without changing anything (no interface changes, no writes).")
@click.option("--json", "json_out", is_flag=True, help="JSON output where supported.")
@click.option("-v", "--verbose", count=True)
@click.version_option(__version__, prog_name="daybreak-wids")
@click.pass_context
def main(ctx: click.Context, config_path: str | None, dry_run: bool, json_out: bool, verbose: int) -> None:
    """daybreak-wids: passive, defensive Wireless IDS for networks you own or administer.

    Authorized defensive monitoring only. This tool does not implement packet
    injection, deauthentication attacks, credential cracking, or password recovery.
    """
    os.umask(PRIVATE_UMASK)  # database, logs and registry contain MAC addresses: owner-only files
    ctx.obj = App(config_path, dry_run, json_out, verbose)


# ---------------------------------------------------------------------------
# sensor
# ---------------------------------------------------------------------------


@main.group()
def sensor() -> None:
    """Discover and check the Wi-Fi sensor adapter."""


@sensor.command("list")
@click.pass_obj
@handle_errors
def sensor_list(app: App) -> None:
    """List Wi-Fi interfaces, PHYs and drivers (read-only)."""
    from .sensor.discovery import Discovery

    cfg = app.config
    runner = CommandRunner()
    ifaces = Discovery(runner).interfaces()
    protected = InterfaceGuard(cfg.sensor.protected_interfaces, runner=runner).protected_set()
    if app.json_out:
        emit_json([dict(i.to_dict(), role=_role(i.name, cfg, protected)) for i in ifaces])
        return
    rows = []
    for i in ifaces:
        rows.append([i.name, i.phy, i.driver, f"{i.bus or '?'} {i.usb_id or ''}".strip(),
                     "/".join(i.bands) or "-", "yes" if i.monitor_supported else "no",
                     i.iftype, i.channel or "-", i.regdomain or "-", i.nm_state or "-",
                     _role(i.name, cfg, protected)])
    click.echo(table(rows, ["IFACE", "PHY", "DRIVER", "BUS", "BANDS(GHz)", "MONITOR", "MODE", "CH", "REG",
                            "NM", "ROLE"]))


def _role(name: str, cfg: Any, protected: set[str]) -> str:
    if name == cfg.sensor.interface:
        return "sensor"
    if name in protected:
        return "protected (never modified)"
    return ""


@sensor.command("check")
@click.pass_obj
@handle_errors
def sensor_check(app: App) -> None:
    """Check the configured sensor without changing anything."""
    from .sensor.check import run_sensor_checks
    from .sensor.discovery import Discovery

    cfg = app.config
    runner = CommandRunner()
    report = run_sensor_checks(cfg, Discovery(runner), InterfaceGuard(cfg.sensor.protected_interfaces, runner=runner))
    kismet = None
    if cfg.backend.type in ("auto", "kismet"):
        from .sensor.kismet import KismetClient, check_kismet
        kismet = check_kismet(KismetClient.from_config(cfg.backend.kismet), cfg)[:2]
        if cfg.backend.type == "auto":  # unreachable Kismet is not fatal: auto falls back to passive
            kismet = [("warn" if lv == "fail" else lv, n, m) for lv, n, m in kismet]
    if app.json_out:
        emit_json({"sensor": report.sensor.to_dict() if report.sensor else None,
                   "checks": [c.to_dict() for c in report.checks],
                   "kismet": [{"level": l, "name": n, "message": m} for l, n, m in (kismet or [])],
                   "ok": report.ok})
    else:
        s = report.sensor
        click.echo("Sensor")
        click.echo(f"Interface : {s.name if s else cfg.sensor.interface}")
        if s:
            click.echo(f"Driver    : {s.driver or '?'}")
            click.echo(f"PHY       : {s.phy or '?'}")
            click.echo(f"Bands     : {' / '.join(s.bands) + ' GHz' if s.bands else '?'}")
            click.echo(f"Monitor   : {'supported' if s.monitor_supported else 'not supported'}")
            click.echo(f"Mode      : {s.iftype or '?'}" + (f" (channel {s.channel})" if s.channel else ""))
            click.echo(f"Regdomain : {s.regdomain or '?'}")
            click.echo(f"NM        : {s.nm_state or 'n/a'}")
        click.echo("")
        for c in report.checks:
            click.echo(f"[{LEVEL_MARK[c.level]}] {c.name}: {c.message}")
            if c.hint and c.level in ("warn", "fail", "info"):
                click.echo(f"         hint: {c.hint}")
        for level, name, msg in kismet or []:
            click.echo(f"[{LEVEL_MARK.get(level, level)}] kismet-{name}: {msg}")
    if not report.ok:
        sys.exit(1)


def _sensor_operation(app: App, action: str, apply: bool, channel: int | None) -> None:
    from .sensor.control import SensorController
    from .sensor.discovery import Discovery, capability_effective

    cfg = app.config
    execute = apply and not app.dry_run
    runner = CommandRunner(dry_run=not execute)
    guard = InterfaceGuard(cfg.sensor.protected_interfaces, runner=runner)
    disc = Discovery(runner)
    disc.interfaces()
    ctl = SensorController(cfg.sensor.interface, guard, runner, nm_running=disc.nm_running,
                           expected_mac=cfg.sensor.expected_mac)
    plan = ctl.plan_prepare(channel) if action == "prepare" else ctl.plan_release()
    click.echo(f"config: {app.config_source()}")
    click.echo(f"{action} {cfg.sensor.interface} (sensor only; protected: "
               f"{', '.join(sorted(guard.protected_set())) or 'none'})")
    for argv in plan:
        click.echo("  " + " ".join(argv))
    missing = guard.missing_configured()
    problem = (f"protected interface(s) {', '.join(missing)} not found: fix sensor.protected_interfaces "
               "(a misspelled name protects nothing)") if missing else None
    if problem is None:
        why = sensor_identity_problem(cfg.sensor, disc.interface(cfg.sensor.interface),
                                      require_disconnected=action == "prepare")
        problem = f"{cfg.sensor.interface}: {why}" if why else None
    if not execute:
        click.echo("\nNot executed" + (" (--dry-run)." if app.dry_run else ". Re-run with --apply to execute."))
        try:
            guard.assert_may_modify(cfg.sensor.interface)
        except SafetyViolation as exc:
            raise click.ClickException(f"would be refused: {exc}") from exc
        if problem:
            raise click.ClickException(f"would be refused: {problem}")
        return
    if problem:
        raise click.ClickException(f"refused: {problem}")
    if "CAP_NET_ADMIN" not in capability_effective():
        # Without it only the polkit-authorised nmcli step would succeed, leaving the sensor
        # unmanaged but still in managed mode.
        raise click.ClickException(f"{action} --apply needs CAP_NET_ADMIN: run it with sudo "
                                   "(see README: Passive backend)")
    report = ctl.prepare(channel) if action == "prepare" else ctl.release()
    for res in report.results:
        mark = "ok" if res.ok else "FAILED"
        click.echo(f"  [{mark}] {' '.join(res.argv)}" + (f": {res.stderr.strip()}" if not res.ok else ""))
    if report.protected_changes:
        for name, diffs in report.protected_changes.items():
            click.echo(f"  [FAIL] protected interface {name} changed: {'; '.join(diffs)}", err=True)
    else:
        click.echo("  protected interfaces unchanged: " + (", ".join(sorted(guard.protected_set())) or "none"))
    if not report.ok:
        raise click.ClickException(report.error or f"{action} incomplete")


@sensor.command("prepare")
@click.option("--channel", type=int, help="Tune the sensor to this channel after enabling monitor mode.")
@click.option("--apply", is_flag=True, help="Execute the plan (requires root). Without it the plan is printed.")
@click.pass_obj
@handle_errors
def sensor_prepare(app: App, channel: int | None, apply: bool) -> None:
    """Put the *sensor* adapter into monitor mode (built-in passive backend only).

    Kismet configures its source itself; this is not needed with Kismet.
    """
    _sensor_operation(app, "prepare", apply, channel)


@sensor.command("release")
@click.option("--apply", is_flag=True, help="Execute the plan (requires root).")
@click.pass_obj
@handle_errors
def sensor_release(app: App, apply: bool) -> None:
    """Return the sensor adapter to managed mode and hand it back to NetworkManager."""
    _sensor_operation(app, "release", apply, None)


# ---------------------------------------------------------------------------
# kismet
# ---------------------------------------------------------------------------


@main.group()
def kismet() -> None:
    """Kismet backend integration."""


@kismet.command("check")
@click.pass_obj
@handle_errors
def kismet_check(app: App) -> None:
    """Check Kismet reachability, datasource and WIDS alert availability."""
    from .sensor.kismet import KismetClient, check_kismet

    results = check_kismet(KismetClient.from_config(app.config.backend.kismet), app.config)
    if app.json_out:
        emit_json([{"level": l, "name": n, "message": m} for l, n, m in results])
    else:
        for level, name, msg in results:
            click.echo(f"[{LEVEL_MARK.get(level, level)}] {name}: {msg}")
    if any(level == "fail" for level, _, _ in results):
        sys.exit(1)


@kismet.command("config")
@click.pass_obj
@handle_errors
def kismet_config(app: App) -> None:
    """Print a suggested kismet_site.conf snippet (source + APSPOOF rules). Writes nothing."""
    from .sensor.kismet import kismet_site_conf

    click.echo(kismet_site_conf(app.config), nl=False)


# ---------------------------------------------------------------------------
# monitor
# ---------------------------------------------------------------------------


@main.group()
def monitor() -> None:
    """Run passive monitoring."""


def _build_live(app: App, backend_kind: str | None, replay: str | None, pcap: str | None,
                realtime: bool, speed: float):
    from .sensor.select import choose_backend
    from .sensor.status import SensorHealthMonitor

    cfg = app.config
    runner = CommandRunner(dry_run=app.dry_run)
    guard = InterfaceGuard(cfg.sensor.protected_interfaces, runner=runner)
    backend = choose_backend(cfg, backend_kind, replay=replay, pcap=pcap, realtime=realtime, speed=speed,
                             guard=guard, runner=runner, log=lambda m: click.echo(m, err=True))
    live = replay is None and pcap is None
    health = SensorHealthMonitor(cfg.sensor.interface, expected_mac=cfg.sensor.expected_mac) if live else None
    recover = None
    if live and backend.name == "passive" and cfg.sensor.auto_prepare and not app.dry_run:
        recover = SensorRecovery(cfg, guard, runner)
    return backend, health, recover, guard


class SensorRecovery:
    """auto_prepare after a USB reset: re-enable monitor mode on the *sensor* only.

    The re-found interface must be the configured sensor (same name, or the expected MAC and
    driver); every command still passes the interface guard. Once a protected interface
    changes during a recovery, recovery stays off for the rest of the run.
    """

    def __init__(self, cfg: Any, guard: InterfaceGuard, runner: CommandRunner):
        self.cfg, self.guard, self.runner = cfg, guard, runner
        self.disabled: str | None = None

    def problem(self, interface: str, found: Any) -> str | None:
        """Why ``interface`` must not be re-prepared (None: it is the configured, idle sensor)."""
        why = sensor_identity_problem(self.cfg.sensor, found, require_disconnected=True)
        if why is None and interface != self.cfg.sensor.interface and not self.cfg.sensor.expected_mac:
            why = "it is not the configured sensor name, and no sensor.expected_mac identifies the adapter"
        return why

    def is_sensor(self, interface: str, found: Any) -> bool:
        return self.problem(interface, found) is None

    def __call__(self, interface: str) -> bool:
        from .sensor.control import SensorController
        from .sensor.discovery import Discovery, capability_effective
        from .sensor.passive import interface_linktype
        from .sensor.select import listen_channels

        if self.disabled:
            click.echo(f"auto_prepare is off for this run: {self.disabled}", err=True)
            return False
        if interface_linktype(interface) is not None:
            return True
        if "CAP_NET_ADMIN" not in capability_effective():
            click.echo(f"sensor {interface} is back in managed mode; run `sudo .venv/bin/daybreak-wids -c CONFIG "
                       "sensor prepare --apply` (NetworkManager may manage it again after a USB reset; see "
                       "`sensor check`)", err=True)
            return False
        disc = Discovery(self.runner)
        disc.interfaces()
        why = self.problem(interface, disc.interface(interface))
        if why:
            click.echo(f"not restoring monitor mode on {interface}: {why}", err=True)
            return False
        channels = listen_channels(self.cfg)
        ctl = SensorController(interface, self.guard, self.runner, nm_running=disc.nm_running,
                               expected_mac=self.cfg.sensor.expected_mac)
        report = ctl.prepare(channels[0] if channels else None)
        if report.protected_changes:
            self.disabled = f"protected interface changed during recovery: {report.protected_changes}"
            click.echo(f"auto_prepare stopped: {self.disabled}", err=True)
            return False
        if not report.ok:
            click.echo(f"could not restore monitor mode on {interface}: {report.error}", err=True)
        return report.ok


class _NullStream:
    """Console sink for --quiet."""

    def write(self, text: str) -> int:
        return len(text)

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


def _run_monitor(app: App, backend, health, recover, duration: float | None, quiet: bool,
                 observers: list | None = None, guard: InterfaceGuard | None = None):
    from .monitor import MonitorRunner
    from .runtime import build_runtime

    stream = _NullStream() if quiet else None
    rt = build_runtime(app.config, dry_run=app.dry_run, console_stream=stream)
    for ob in observers or []:
        rt.pipeline.observers.append(ob)
    stop = threading.Event()

    def _stop(signum, frame):  # noqa: ARG001
        stop.set()

    old = {s: signal.signal(s, _stop) for s in (signal.SIGINT, signal.SIGTERM)}
    live = guard is not None and health is not None
    if live:
        guard.pin()  # these stay protected for the whole run, even if the default route moves
    before = guard.snapshot_protected() if live else None
    runner = MonitorRunner(rt, backend, health=health, duration=duration, recover=recover, stop=stop,
                           on_message=lambda m: click.echo(m, err=True), guard=guard if live else None)
    try:
        summary = runner.run()
    finally:
        for s, h in old.items():
            signal.signal(s, h)
        rt.close()
    if before is not None:
        changes = guard.verify_unchanged(before, guard.snapshot_protected())
        summary["protected_interfaces_changed"] = changes
    return rt, summary


@monitor.command("start")
@click.option("--backend", "backend_kind", type=click.Choice(["auto", "kismet", "passive"]),
              help="Override backend.type from the configuration.")
@click.option("--replay", type=click.Path(exists=True, dir_okay=False), help="Replay a JSONL metadata stream.")
@click.option("--pcap", type=click.Path(exists=True, dir_okay=False), help="Analyse a pcap/pcapng file offline.")
@click.option("--realtime", is_flag=True, help="Replay with original timing.")
@click.option("--speed", type=float, default=1.0, show_default=True, help="Replay speed factor (with --realtime).")
@click.option("--duration", type=float, help="Stop after this many seconds.")
@click.option("--quiet", is_flag=True, help="Do not print alerts to the console.")
@click.pass_obj
@handle_errors
def monitor_start(app: App, backend_kind, replay, pcap, realtime, speed, duration, quiet) -> None:
    """Start passive monitoring (Ctrl-C to stop)."""
    click.echo(BANNER, err=True)
    if app.dry_run:
        click.echo("dry-run: nothing is written to the database, logs or desktop; alerts are printed only.",
                   err=True)
    if replay is None and pcap is None:
        click.echo(f"config: {app.config_source()}", err=True)
    backend, health, recover, guard = _build_live(app, backend_kind, replay, pcap, realtime, speed)
    rt, summary = _run_monitor(app, backend, health, recover, duration, quiet, guard=guard)
    st = summary["stats"]
    click.echo(f"\nprocessed {st.get('processed', 0)} events ({st.get('duplicates', 0)} duplicates, "
               f"{st.get('out_of_scope', 0)} out of scope, {backend.stats.get('malformed', 0)} malformed); "
               f"alerts delivered {summary['alerts'].get('delivered', 0)}, "
               f"suppressed {summary['alerts'].get('suppressed', 0)}; threat level {summary['threat_level']}"
               + (f"; flood sampling: {st.get('events_not_stored', 0)} events and {st.get('aps_not_stored', 0)} "
                  "AP rows not stored" if st.get("events_not_stored") or st.get("aps_not_stored") else ""),
               err=True)
    if backend.errors and app.verbose:
        for e in backend.errors[-10:]:
            click.echo(f"  input error: {e}", err=True)
    changes = summary.get("protected_interfaces_changed")
    if changes:
        click.echo(f"WARNING: protected interface state changed during the run: {changes} (daybreak-wids sends "
                   "no commands to protected interfaces)", err=True)
    elif changes == {}:
        click.echo("protected interfaces unchanged", err=True)


@monitor.command("status")
@click.pass_obj
@handle_errors
def monitor_status(app: App) -> None:
    """Show the state of the running (or last) monitor."""
    from .monitor import read_status, status_path

    cfg = app.config
    st = read_status(status_path(cfg))
    db = app.database(required=False)
    sensor_rows = db.latest_sensor_status(limit=5) if db else []
    recent = db.list_alerts(since=time.time() - 300, limit=20) if db else []
    if app.json_out:
        emit_json({"monitor": st, "sensor_status": sensor_rows, "recent_alerts": recent})
        return
    if st is None:
        click.echo("monitor: never started (no status file)")
    else:
        state = "running" if st.get("alive") else ("stopped" if st.get("state") == "stopped" else "not running (stale)")
        click.echo(f"monitor   : {state} (pid {st.get('pid')}), updated {format_local(st['updated'])}")
        b = st.get("backend") or {}
        click.echo(f"backend   : {b.get('name')} - {b.get('detail', '')}"
                   + (f" [error: {st['backend_error']}]" if st.get("backend_error") else ""))
        s = st.get("sensor") or {}
        online = {True: "ONLINE", False: "LOST", None: "unknown"}[s.get("online")]
        click.echo(f"sensor    : {s.get('interface')} {online}")
        stats = st.get("stats", {})
        click.echo(f"events    : {stats.get('processed', 0)} processed, last {st.get('last_event') or '-'}")
        click.echo("by type   : " + ", ".join(f"{k} {v}" for k, v in sorted(st.get("events_by_type", {}).items())))
        click.echo(f"alerts    : {st.get('alerts', {}).get('delivered', 0)} delivered, "
                   f"{st.get('alerts', {}).get('suppressed', 0)} suppressed")
        click.echo(f"threat    : {st.get('threat_level')}")
    for row in sensor_rows:
        click.echo(f"  {format_local(row['timestamp'])} {row['status']:<20} {row.get('interface') or ''}")
    if recent:
        from .scoring import threat_level
        click.echo(f"last 5 min: {len(recent)} alert(s), threat level {threat_level(recent)}")


# ---------------------------------------------------------------------------
# network
# ---------------------------------------------------------------------------


@main.group()
def network() -> None:
    """Protected network registry."""


@network.command("list")
@click.pass_obj
@handle_errors
def network_list(app: App) -> None:
    """List protected networks (unconfigured ones show observed candidate BSSIDs)."""
    cfg = app.config
    db = app.database(required=False)
    out = []
    for n in cfg.protected_networks:
        candidates = []
        if db is not None:
            candidates = [r["bssid"] for r in db.list_aps(ssid=n.ssid) if r["bssid"] not in n.bssids]
        out.append({"name": n.name, "ssid": n.ssid, "status": n.status, "bssids": n.bssids,
                    "channels": n.channels, "expected": n.security.expected, "pmf": n.security.pmf,
                    "origin": n.origin, "observed_unregistered": candidates})
    if app.json_out:
        emit_json(out)
        return
    if not out:
        click.echo("no protected networks; add one with `daybreak-wids network add`")
        return
    rows = [[n["name"], n["ssid"], n["status"], ",".join(n["bssids"]) or "-", ",".join(map(str, n["channels"])) or "-",
             "/".join(n["expected"]) or "-", n["pmf"] or "-", n["origin"]] for n in out]
    click.echo(table(rows, ["NAME", "SSID", "STATUS", "BSSIDS", "CHANNELS", "EXPECTED", "PMF", "SOURCE"]))
    for n in out:
        if n["observed_unregistered"]:
            label = "candidates (not adopted)" if n["status"] == "unconfigured" else "unregistered BSSIDs seen"
            click.echo(f"  {n['name']}: {label}: {', '.join(n['observed_unregistered'])}")


@network.command("add")
@click.option("--name")
@click.option("--ssid")
@click.option("--bssid", "bssids", multiple=True, help="Registered BSSID (repeatable).")
@click.option("--channel", "channels", type=int, multiple=True, help="Expected channel (repeatable).")
@click.option("--expect", "expected", multiple=True, type=click.Choice(["WPA2", "WPA3", "WPA", "OWE", "OPEN"],
              case_sensitive=False), help="Expected protocol (repeatable), e.g. --expect WPA2 --expect WPA3.")
@click.option("--pmf", type=click.Choice(["disabled", "capable", "required"]), help="Expected PMF level.")
@click.option("--replace", is_flag=True, help="Replace an existing registry entry with the same name.")
@click.option("-i", "--interactive", is_flag=True, help="Prompt for missing values.")
@click.pass_obj
@handle_errors
def network_add(app: App, name, ssid, bssids, channels, expected, pmf, replace, interactive) -> None:
    """Register a network you administer (only networks you own or are authorized to monitor)."""
    from .registry import RegistryError, add_network

    interactive = interactive or (sys.stdin.isatty() and (not name or not ssid))
    if interactive:
        name = name or click.prompt("Name")
        ssid = ssid or click.prompt("SSID")
        if not bssids:
            raw = click.prompt("BSSIDs (comma separated, empty = unconfigured)", default="", show_default=False)
            bssids = tuple(b.strip() for b in raw.split(",") if b.strip())
        if not channels:
            raw = click.prompt("Channels (comma separated, optional)", default="", show_default=False)
            channels = tuple(int(c) for c in raw.split(",") if c.strip())
        if not expected:
            raw = click.prompt("Expected security (e.g. WPA2,WPA3; optional)", default="", show_default=False)
            expected = tuple(e.strip().upper() for e in raw.split(",") if e.strip())
    if not name or not ssid:
        raise click.UsageError("--name and --ssid are required")
    try:
        net = add_network(app.config, name=name, ssid=ssid, bssids=bssids, channels=channels,
                          expected=[e.upper() for e in expected], pmf=pmf, replace=replace, dry_run=app.dry_run)
    except RegistryError as exc:
        raise click.ClickException(str(exc)) from exc
    import yaml
    click.echo(yaml.safe_dump({"protected_networks": [net.to_yaml_dict()]}, sort_keys=False).rstrip())
    if app.dry_run:
        click.echo(f"dry-run: not written to {app.config.registry_path}")
    else:
        click.echo(f"saved to {app.config.registry_path} ({net.status})")
    if not net.bssids:
        click.echo("note: without BSSIDs the network is 'unconfigured'; no nearby AP is adopted automatically. "
                   "`network list` shows observed candidates.")


@network.command("remove")
@click.argument("name")
@click.pass_obj
@handle_errors
def network_remove(app: App, name: str) -> None:
    """Remove a network added with `network add`."""
    from .registry import RegistryError, remove_network

    try:
        removed = remove_network(app.config, name, dry_run=app.dry_run)
    except RegistryError as exc:
        raise click.ClickException(str(exc)) from exc
    if not removed:
        raise click.ClickException(f"no registry network named {name!r}")
    click.echo(("dry-run: would remove " if app.dry_run else "removed ") + name)


# ---------------------------------------------------------------------------
# baseline
# ---------------------------------------------------------------------------


@main.group()
def baseline() -> None:
    """Learn and inspect normal behaviour."""


@baseline.command("create")
@click.option("--duration", type=float, help="Observe live for this many seconds (default: detection.baseline.default_duration).")
@click.option("--replay", type=click.Path(exists=True, dir_okay=False), help="Learn from a JSONL metadata stream.")
@click.option("--pcap", type=click.Path(exists=True, dir_okay=False), help="Learn from a capture file.")
@click.option("--from-db", is_flag=True, help="Learn from events already stored in the database.")
@click.option("--since", default="24h", show_default=True, help="With --from-db: how far back.")
@click.option("--backend", "backend_kind", type=click.Choice(["auto", "kismet", "passive"]))
@click.pass_obj
@handle_errors
def baseline_create(app: App, duration, replay, pcap, from_db, since, backend_kind) -> None:
    """Build a baseline and store it in SQLite (use a period without known attacks)."""
    from .baseline.engine import BaselineBuilder, save_baselines
    from .registry import NetworkRegistry
    from .storage import Database

    cfg = app.config
    builder = BaselineBuilder(cfg, NetworkRegistry(cfg.protected_networks))
    if from_db:
        db = app.database()
        start = parse_since(since)
        for row in db.query_events(since=start):
            builder.add(db.event_from_row(row))
        for row in db.list_aps():
            builder.add_ap_row(row)
        db.close()
    else:
        backend, health, recover, guard = _build_live(app, backend_kind, replay, pcap, False, 1.0)
        if replay is None and pcap is None:
            duration = duration or cfg.detection.baseline.default_duration
            click.echo(f"learning for {duration:g}s from {backend.name}; alerts are still raised", err=True)
        _run_monitor(app, backend, health, recover, duration if (replay is None and pcap is None) else None,
                     quiet=True, observers=[builder.add], guard=guard)
    docs = builder.metrics()
    if not docs or builder.events == 0:
        raise click.ClickException("no events for protected networks were observed; nothing to learn")
    if app.json_out:
        emit_json(docs)
    else:
        for name, doc in docs.items():
            _print_baseline(name, doc)
    if app.dry_run:
        click.echo("dry-run: baseline not saved")
        return
    db = Database(cfg.database_path)
    ids = db.sync_networks(cfg.protected_networks)
    saved = save_baselines(db, {k: v for k, v in docs.items() if v["events"]}, ids)
    db.close()
    click.echo(f"saved baseline(s): {', '.join(f'{k} (#{v})' for k, v in saved.items()) or 'none'}")


def _print_baseline(name: str, doc: dict[str, Any]) -> None:
    click.echo(f"Baseline: {name} ({doc.get('ssid')})")
    if not doc.get("events"):
        click.echo("  no events observed\n")
        return
    start, end = doc["window"]
    click.echo(f"  window   : {format_local(start)} - {format_local(end)} ({doc['duration']:g}s, "
               f"{doc['buckets']} x {doc['bucket']:g}s buckets)")
    for metric, r in doc["rates"].items():
        click.echo(f"  {metric:<11}: median {r['median']:g}/bucket, mean {r['mean']:g}, p95 {r['p95']:g}, "
                   f"max {r['max']:g}")
    c = doc["clients"]
    click.echo(f"  clients  : {c['min']}-{c['max']} per bucket (mean {c['mean']:g})")
    sec = doc.get("security")
    click.echo(f"  security : {sec['mode'] + ', PMF ' + sec['pmf'] if sec else 'not observed'}")
    click.echo(f"  channels : {', '.join(map(str, doc['known_channels'])) or '-'}")
    for bssid, info in doc["bssids"].items():
        r = info.get("rssi")
        rssi = f"RSSI {r['mean']:g}±{r['std']:g} dBm (n={r['n']})" if r else "RSSI n/a"
        click.echo(f"  {bssid}: ch {','.join(map(str, info['channels'])) or '-'}, {rssi}, "
                   f"{info['security']['mode'] if info.get('security') else '?'}")
    if doc.get("candidate_bssids"):
        click.echo(f"  unregistered BSSIDs seen: {', '.join(doc['candidate_bssids'])}")
    click.echo("")


@baseline.command("show")
@click.option("--network", "network_name")
@click.pass_obj
@handle_errors
def baseline_show(app: App, network_name: str | None) -> None:
    """Show the active baselines."""
    db = app.database()
    rows = [r for r in db.active_baselines() if not network_name or r["network"] == network_name]
    if app.json_out:
        emit_json(rows)
        return
    if not rows:
        click.echo("no active baseline; run `daybreak-wids baseline create`")
        return
    for r in rows:
        click.echo(f"#{r['id']} created {format_local(r['created_at'])}")
        _print_baseline(r["network"], r["metrics"])


# ---------------------------------------------------------------------------
# alerts / report / audit
# ---------------------------------------------------------------------------


@main.command("alerts")
@click.option("--since", default="24h", show_default=True)
@click.option("--severity", "min_severity", type=click.Choice([s.name for s in Severity], case_sensitive=False),
              default="INFO", show_default=True, help="Minimum severity.")
@click.option("--type", "alert_type")
@click.option("--limit", type=int, default=50, show_default=True)
@click.option("--unacked", is_flag=True, help="Only unacknowledged alerts.")
@click.option("--ack", "ack_id", type=int, help="Acknowledge alert ID.")
@click.option("--details", is_flag=True, help="Show score breakdown.")
@click.pass_obj
@handle_errors
def alerts_cmd(app: App, since, min_severity, alert_type, limit, unacked, ack_id, details) -> None:
    """List (or acknowledge) alerts."""
    from .scoring import explain

    db = app.database()
    if ack_id is not None:
        if app.dry_run:
            click.echo(f"dry-run: would acknowledge #{ack_id}")
        elif db.acknowledge_alert(ack_id):
            click.echo(f"acknowledged #{ack_id}")
        else:
            raise click.ClickException(f"no alert #{ack_id}")
        return
    rows = db.list_alerts(since=parse_since(since), min_severity=Severity.parse(min_severity),
                          alert_type=alert_type, unacknowledged=unacked, limit=limit)
    if app.json_out:
        emit_json(rows)
        return
    if not rows:
        click.echo("no alerts")
        return
    for r in rows:
        ack = " (ack)" if r["acknowledged"] else ""
        sup = f" +{r['suppressed_count']} suppressed" if r["suppressed_count"] else ""
        click.echo(f"#{r['id']:<5} {format_local(r['timestamp'])} {r['severity']:<8} {r['score']:>3} "
                   f"{r['alert_type']:<36} {r['bssid'] or '':<17}{ack}{sup}")
        if details:
            for line in explain(r["score"], r["reason"].get("components", []))[1:]:
                click.echo(f"        {printable(line)}")
            if r["summary"]:
                click.echo(f"        {printable(r['summary'])}")


@main.command("report")
@click.option("--since", default="24h", show_default=True)
@click.option("--format", "fmt", type=click.Choice(["text", "json"]), default="text", show_default=True)
@click.pass_obj
@handle_errors
def report_cmd(app: App, since, fmt) -> None:
    """Summary report: sensor, alerts, events, AP security, baselines."""
    from .report import build_report, render_report

    db = app.database()
    rep = build_report(app.config, db, since=parse_since(since))
    if fmt == "json" or app.json_out:
        emit_json(rep)
    else:
        click.echo(render_report(rep))


@main.group()
def audit() -> None:
    """Configuration audits (passive; never changes AP settings)."""


def _networks(app: App, name: str | None):
    nets = [n for n in app.config.protected_networks if not name or n.name == name]
    if name and not nets:
        raise click.ClickException(f"no protected network named {name!r}")
    if not nets:
        raise click.ClickException("no protected networks configured")
    return nets


@audit.command("security")
@click.option("--network", "network_name")
@click.pass_obj
@handle_errors
def audit_security(app: App, network_name) -> None:
    """WPA2/WPA3/PMF/WPS audit from observed beacons."""
    from .detectors.security import audit_network, observations_from_rows, render_audit

    db = app.database(required=False)
    results = []
    for net in _networks(app, network_name):
        obs = observations_from_rows(db.list_aps(ssid=net.ssid)) if db else []
        results.append(audit_network(net, obs))
    if app.json_out:
        emit_json([a.to_dict() for a in results])
        return
    for a in results:
        click.echo(render_audit(a))
        click.echo("")
    if db is None:
        click.echo("(no observations yet: run `daybreak-wids monitor start` first)")


@audit.command("policy")
@click.option("--network", "network_name")
@click.pass_obj
@handle_errors
def audit_policy(app: App, network_name) -> None:
    """Passphrase/router hygiene checklist. Never asks for the Wi-Fi passphrase."""
    from .detectors.security import audit_network, observations_from_rows
    from .policy import policy_checklist, render_checklist

    db = app.database(required=False)
    out = []
    for net in _networks(app, network_name):
        prof = None
        if db is not None:
            prof = audit_network(net, observations_from_rows(db.list_aps(ssid=net.ssid))).profile
        items = policy_checklist(prof)
        out.append((net, items))
    if app.json_out:
        emit_json({n.name: [i.to_dict() for i in items] for n, items in out})
        return
    for net, items in out:
        click.echo(render_checklist(items, net.ssid))
        click.echo("")


# ---------------------------------------------------------------------------
# dashboard (optional)
# ---------------------------------------------------------------------------


@main.command("dashboard")
@click.option("--host", help="Bind address (default: dashboard.host, 127.0.0.1).")
@click.option("--port", type=int, help="Port (default: dashboard.port).")
@click.pass_obj
@handle_errors
def dashboard_cmd(app: App, host, port) -> None:
    """Local read-only web dashboard (requires the 'dashboard' extra)."""
    try:
        from .dashboard.app import serve
    except ImportError as exc:
        raise click.ClickException("dashboard needs extra packages: pip install 'daybreak-wids[dashboard]'") from exc
    cfg = app.config
    serve(cfg, host=host or cfg.dashboard.host, port=port or cfg.dashboard.port,
          allow_remote=cfg.dashboard.allow_remote)


if __name__ == "__main__":  # pragma: no cover
    main()
