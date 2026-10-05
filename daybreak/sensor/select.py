"""Backend selection: Kismet first, built-in passive capture as fallback."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable

from ..config import Config
from ..safety import CommandRunner, InterfaceGuard
from .backend import Backend
from .control import SensorController
from .kismet import KismetAuthError, KismetBackend, KismetClient, KismetError
from .passive import PassiveBackend
from .pcapfile import PcapFileBackend
from .replay import ReplayBackend


def listen_channels(config: Config) -> list[int]:
    if config.sensor.channels:
        return list(dict.fromkeys(config.sensor.channels))
    return list(dict.fromkeys(c for n in config.protected_networks for c in n.channels))


def passive_backend(config: Config, *, guard: InterfaceGuard, runner: CommandRunner,
                    interface: str | None = None) -> PassiveBackend:
    iface = interface or config.backend.passive.interface or config.sensor.interface
    controller = SensorController(iface, guard, runner, expected_mac=config.sensor.expected_mac)
    backend: PassiveBackend

    def tune(channel: int) -> None:
        # Follow a rename after a USB reset; the controller still refuses any interface whose
        # MAC is not the sensor's (another adapter may have taken the old name).
        controller.interface = backend.interface
        res = controller.set_channel(channel)
        if not res.ok:
            raise RuntimeError(res.stderr.strip() or f"iw exited {res.returncode}")

    # --dry-run never retunes the radio, so do not pretend to hop.
    backend = PassiveBackend(iface, sensor_name=config.sensor.interface, channels=listen_channels(config),
                             dwell=config.sensor.dwell_time, set_channel=None if runner.dry_run else tune)
    return backend


def choose_backend(config: Config, kind: str | None = None, *, replay: str | Path | None = None,
                   pcap: str | Path | None = None, realtime: bool = False, speed: float = 1.0,
                   guard: InterfaceGuard | None = None, runner: CommandRunner | None = None,
                   log: Callable[[str], None] = print) -> Backend:
    if replay is not None:
        return ReplayBackend(replay, sensor_name="replay", realtime=realtime, speed=speed)
    if pcap is not None:
        return PcapFileBackend(pcap, sensor_name="pcap")
    kind = kind or config.backend.type
    runner = runner or CommandRunner()
    guard = guard or InterfaceGuard(config.sensor.protected_interfaces, runner=runner)
    if kind == "replay":
        raise ValueError("backend 'replay' needs --replay FILE")
    if kind in ("auto", "kismet"):
        kcfg = config.backend.kismet
        if os.geteuid() == 0 and not os.environ.get(kcfg.api_key_env):
            log(f"running as root without ${kcfg.api_key_env}: sudo drops environment variables "
                f"(use `sudo --preserve-env={kcfg.api_key_env} ...`)")
        client = KismetClient.from_config(kcfg)
        reachable = True
        try:
            client.system_status()
        except KismetAuthError as exc:
            # Kismet is running and owns the sensor: falling back to the passive backend would
            # retune the adapter Kismet is driving.
            raise ValueError(f"{exc}. Kismet is running at {client.base}, so daybreak-wids will not fall "
                             "back to the passive backend; fix the API key, or stop Kismet and use "
                             "--backend passive") from exc
        except KismetError as exc:
            reachable = False
            if kind == "auto":
                log(f"Kismet unavailable ({exc}); using the built-in passive backend")
        if reachable or kind == "kismet":
            def tap(iface: str) -> Backend:
                return PassiveBackend(iface, sensor_name=config.sensor.interface)  # Kismet owns channels
            return KismetBackend(config.backend.kismet, sensor_interface=config.sensor.interface,
                                 client=client, frame_tap_factory=tap)
    return passive_backend(config, guard=guard, runner=runner)
