"""Test doubles: a fake sysfs tree and a scripted command runner (no host access)."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Callable

from daybreak.safety import CommandResult, CommandRunner, checked_command

HOST = Path(__file__).parent / "fixtures" / "host"


class FakeSysfs:
    def __init__(self, root: Path):
        self.root = root
        self.net = root / "class" / "net"
        self.net.mkdir(parents=True, exist_ok=True)

    def add_wireless(self, name: str, *, phy: str, mac: str, driver: str, usb_id: str | None = None,
                     operstate: str = "down") -> Path:
        iface = self.net / name
        iface.mkdir(parents=True, exist_ok=True)
        (iface / "address").write_text(mac.lower() + "\n")
        (iface / "operstate").write_text(operstate + "\n")
        phy_dir = self.root / "ieee80211" / phy
        phy_dir.mkdir(parents=True, exist_ok=True)
        (phy_dir / "name").write_text(phy + "\n")
        os.symlink(phy_dir, iface / "phy80211")
        drv = self.root / "drivers" / driver
        drv.mkdir(parents=True, exist_ok=True)
        if usb_id:
            usbdev = self.root / "devices" / "usb2" / f"2-1-{name}"
            dev = usbdev / f"2-1:1.3-{name}"
            dev.mkdir(parents=True, exist_ok=True)
            vid, pid = usb_id.split(":")
            (usbdev / "idVendor").write_text(vid + "\n")
            (usbdev / "idProduct").write_text(pid + "\n")
            bus = self.root / "bus" / "usb"
        else:
            dev = self.root / "devices" / "pci0000:00" / f"dev-{name}"
            dev.mkdir(parents=True, exist_ok=True)
            bus = self.root / "bus" / "pci"
        bus.mkdir(parents=True, exist_ok=True)
        if not (dev / "driver").exists():
            os.symlink(drv, dev / "driver")
            os.symlink(bus, dev / "subsystem")
        os.symlink(dev, iface / "device")
        return iface

    def add_wired(self, name: str, mac: str = "02:00:00:00:00:99") -> None:
        iface = self.net / name
        iface.mkdir(parents=True, exist_ok=True)
        (iface / "address").write_text(mac + "\n")
        (iface / "operstate").write_text("up\n")

    def remove(self, name: str) -> None:
        shutil.rmtree(self.net / name)

    def set_operstate(self, name: str, state: str) -> None:
        (self.net / name / "operstate").write_text(state + "\n")


def write_route_file(path: Path, default_iface: str | None) -> Path:
    lines = ["Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT"]
    if default_iface:
        lines.append(f"{default_iface}\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0")
        lines.append(f"{default_iface}\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0")
    path.write_text("\n".join(lines) + "\n")
    return path


class FakeRunner(CommandRunner):
    """Scripted ``CommandRunner``: answers inspection commands from fixtures."""

    def __init__(self, responses: dict[tuple[str, ...], CommandResult | str] | None = None,
                 *, dry_run: bool = False,
                 on_mutate: Callable[[list[str]], CommandResult | None] | None = None):
        super().__init__(dry_run=dry_run)
        self.responses = dict(responses or {})
        self.on_mutate = on_mutate
        self.executed: list[list[str]] = []

    def run(self, argv, *, mutating: bool = False, guard=None) -> CommandResult:
        argv = list(argv)
        mutating = checked_command(argv, mutating, guard)  # the runtime allow-list and guard apply to every test
        self.history.append(argv)
        if mutating:
            if self.dry_run:
                return CommandResult(argv, 0, "", "dry-run: not executed")
            self.executed.append(argv)
            if self.on_mutate:
                res = self.on_mutate(argv)
                if res is not None:
                    return res
            return CommandResult(argv, 0)
        resp = self.responses.get(tuple(argv))
        if resp is None:
            return CommandResult(argv, 1, "", "not scripted")
        if isinstance(resp, str):
            return CommandResult(argv, 0, resp)
        return resp


def host_runner(**kwargs) -> FakeRunner:
    """Runner that answers like the reference host (ALFA on phy3, wlo1 on phy0)."""
    alfa_info = (HOST / "iw_dev_alfa_info.txt").read_text()
    wlo1_info = (HOST / "iw_dev_wlo1_info.txt").read_text()
    responses = {
        ("iw", "phy", "phy3", "info"): (HOST / "iw_phy3_info.txt").read_text(),
        ("iw", "phy", "phy0", "info"): "Wiphy phy0\n\tSupported interface modes:\n\t\t * managed\n"
                                       "\tBand 1:\n\t\tFrequencies:\n\t\t\t* 2412.0 MHz [1] (22.0 dBm)\n",
        ("iw", "reg", "get"): (HOST / "iw_reg_get.txt").read_text(),
        ("iw", "dev", "wlx00c0cab85c32", "info"): alfa_info,
        ("iw", "dev", "wlo1", "info"): wlo1_info,
        ("nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status"):
            (HOST / "nmcli_device_status.txt").read_text(),
    }
    return FakeRunner(responses, **kwargs)


def host_sysfs(tmp_path: Path) -> tuple[FakeSysfs, Path]:
    fs = FakeSysfs(tmp_path / "sys")
    fs.add_wireless("wlo1", phy="phy0", mac="02:00:00:00:00:01", driver="iwlwifi", operstate="up")
    fs.add_wireless("wlx00c0cab85c32", phy="phy3", mac="00:c0:ca:b8:5c:32", driver="mt7921u",
                    usb_id="0e8d:7961")
    fs.add_wired("enp1s0")
    route = write_route_file(tmp_path / "route", "wlo1")
    return fs, route
