"""Read-only discovery of Linux Wi-Fi PHYs and interfaces.

Uses sysfs plus ``iw``/``nmcli`` *inspection* commands only. Nothing here
changes interface state.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..dot11.ieee80211 import freq_to_channel
from ..safety import CommandRunner, default_route_interfaces

__all__ = ["freq_to_channel"]


def band_of(freq: int | float) -> str | None:
    return freq_to_channel(freq)[1]


@dataclass
class PhyInfo:
    name: str
    supported_modes: list[str] = field(default_factory=list)
    bands: list[str] = field(default_factory=list)
    channels: dict[str, list[int]] = field(default_factory=dict)          # enabled channels per band
    disabled_channels: dict[str, list[int]] = field(default_factory=dict)

    @property
    def monitor_supported(self) -> bool:
        return "monitor" in self.supported_modes


@dataclass
class WirelessInterface:
    name: str
    phy: str | None = None
    driver: str | None = None
    mac: str | None = None
    operstate: str | None = None
    iftype: str | None = None
    channel: int | None = None
    frequency: int | None = None
    width: str | None = None
    ssid: str | None = None
    bus: str | None = None
    usb_id: str | None = None
    nm_state: str | None = None
    default_route: bool = False
    regdomain: str | None = None
    phy_info: PhyInfo | None = None

    @property
    def bands(self) -> list[str]:
        return self.phy_info.bands if self.phy_info else []

    @property
    def monitor_supported(self) -> bool | None:
        return self.phy_info.monitor_supported if self.phy_info else None

    @property
    def nm_managed(self) -> bool | None:
        if self.nm_state is None:
            return None
        return self.nm_state != "unmanaged"

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface": self.name, "phy": self.phy, "driver": self.driver, "mac": self.mac,
            "operstate": self.operstate, "type": self.iftype, "channel": self.channel,
            "frequency": self.frequency, "width": self.width, "bus": self.bus,
            "usb_id": self.usb_id, "bands": self.bands, "monitor_supported": self.monitor_supported,
            "nm_state": self.nm_state, "nm_managed": self.nm_managed,
            "default_route": self.default_route, "regdomain": self.regdomain,
        }


# ---------------------------------------------------------------------------
# Parsers (pure functions; unit-tested against captured output)
# ---------------------------------------------------------------------------

_FREQ_LINE = re.compile(r"^\*\s+(\d+(?:\.\d+)?)\s+MHz\s+\[(\d+)\](.*)$")


def parse_iw_phy_info(name: str, text: str) -> PhyInfo:
    info = PhyInfo(name=name)
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not raw.startswith("\t\t") and raw.startswith("\t"):
            # top level attribute of the wiphy
            section = None
            if line.startswith("Supported interface modes"):
                section = "modes"
            elif re.match(r"Band \d+:", line):
                section = "band"
            elif line.startswith("Frequencies:"):
                section = "freqs"
            continue
        if section == "modes" and line.startswith("* "):
            info.supported_modes.append(line[2:].strip())
            continue
        if line.startswith("Frequencies:"):
            section = "freqs"
            continue
        if section in ("band", "freqs"):
            m = _FREQ_LINE.match(line)
            if not m:
                continue
            freq = float(m.group(1))
            chan = int(m.group(2))
            band = band_of(freq)
            if band is None:
                continue
            if band not in info.bands:
                info.bands.append(band)
            if "disabled" in m.group(3):
                info.disabled_channels.setdefault(band, []).append(chan)
            else:
                info.channels.setdefault(band, []).append(chan)
    order = {"2.4": 0, "5": 1, "6": 2}
    info.bands.sort(key=lambda b: order.get(b, 9))
    return info


def parse_iw_dev_info(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("type "):
            out["type"] = line.split(None, 1)[1]
        elif line.startswith("ssid "):
            out["ssid"] = line.split(None, 1)[1]
        elif line.startswith("wiphy "):
            out["wiphy"] = line.split(None, 1)[1]
        elif line.startswith("addr "):
            out["addr"] = line.split(None, 1)[1].upper()
        elif line.startswith("channel "):
            m = re.match(r"channel (\d+) \((\d+) MHz\)(?:, width: ([^,]+))?", line)
            if m:
                out["channel"] = int(m.group(1))
                out["frequency"] = int(m.group(2))
                if m.group(3):
                    out["width"] = m.group(3).strip()
    return out


def parse_iw_reg_get(text: str) -> tuple[str | None, dict[str, str]]:
    """Return (global country, {phy name: country}) from ``iw reg get``."""
    global_cc: str | None = None
    per_phy: dict[str, str] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line == "global":
            current = "global"
            continue
        m = re.match(r"phy#(\d+)", line)
        if m:
            current = f"phy{m.group(1)}"
            continue
        m = re.match(r"country ([0-9A-Z]{2}):", line)
        if m and current:
            if current == "global":
                global_cc = m.group(1)
            else:
                per_phy[current] = m.group(1)
            current = None
    return global_cc, per_phy


def parse_nmcli_device_status(text: str) -> dict[str, str]:
    """``nmcli -t -f DEVICE,TYPE,STATE device status`` -> {device: state}."""
    out = {}
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 3:
            out[parts[0]] = parts[2].split(" (")[0]
    return out


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


class Discovery:
    def __init__(self, runner: CommandRunner | None = None, *,
                 sysfs_root: str | Path = "/sys/class/net",
                 route_file: str | Path = "/proc/net/route"):
        self.runner = runner or CommandRunner()
        self.sysfs_root = Path(sysfs_root)
        self.route_file = Path(route_file)
        self._phy_cache: dict[str, PhyInfo] = {}
        self.nm_running: bool | None = None
        self.global_regdomain: str | None = None
        self.phy_regdomains: dict[str, str] = {}

    # -- sysfs -----------------------------------------------------------------
    def _read(self, iface: str, rel: str) -> str | None:
        try:
            return (self.sysfs_root / iface / rel).read_text().strip()
        except OSError:
            return None

    def wireless_names(self) -> list[str]:
        if not self.sysfs_root.is_dir():
            return []
        return sorted(e.name for e in self.sysfs_root.iterdir()
                      if (e / "phy80211").exists() or (e / "wireless").exists())

    def _phy_name(self, iface: str) -> str | None:
        name = self._read(iface, "phy80211/name")
        if name:
            return name
        link = self.sysfs_root / iface / "phy80211"
        return os.path.basename(os.path.realpath(link)) if link.exists() else None

    def _driver(self, iface: str) -> str | None:
        link = self.sysfs_root / iface / "device" / "driver"
        try:
            return os.path.basename(os.path.realpath(link)) if link.exists() else None
        except OSError:
            return None

    def _bus_info(self, iface: str) -> tuple[str | None, str | None]:
        dev = self.sysfs_root / iface / "device"
        try:
            real = Path(os.path.realpath(dev))
        except OSError:
            return None, None
        subsystem = dev / "subsystem"
        bus = os.path.basename(os.path.realpath(subsystem)) if subsystem.exists() else None
        if bus == "usb" or "/usb" in str(real):
            for candidate in (real, real.parent):
                vid, pid = candidate / "idVendor", candidate / "idProduct"
                if vid.exists() and pid.exists():
                    return "usb", f"{vid.read_text().strip()}:{pid.read_text().strip()}"
            return "usb", None
        return bus, None

    # -- commands ----------------------------------------------------------------
    def phy_info(self, phy: str) -> PhyInfo | None:
        if phy in self._phy_cache:
            return self._phy_cache[phy]
        res = self.runner.run(["iw", "phy", phy, "info"])
        if not res.ok:
            return None
        info = parse_iw_phy_info(phy, res.stdout)
        self._phy_cache[phy] = info
        return info

    def _load_regdomain(self) -> None:
        res = self.runner.run(["iw", "reg", "get"])
        if res.ok:
            self.global_regdomain, self.phy_regdomains = parse_iw_reg_get(res.stdout)

    def _load_nm(self) -> dict[str, str]:
        res = self.runner.run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status"])
        if not res.ok:
            self.nm_running = False
            return {}
        self.nm_running = True
        return parse_nmcli_device_status(res.stdout)

    def interfaces(self) -> list[WirelessInterface]:
        names = self.wireless_names()
        if not names:
            return []
        self._load_regdomain()
        nm = self._load_nm()
        routes = default_route_interfaces(self.route_file)
        out = []
        for name in names:
            out.append(self._describe(name, nm, routes))
        return out

    def interface(self, name: str) -> WirelessInterface | None:
        if name not in self.wireless_names():
            return None
        self._load_regdomain()
        return self._describe(name, self._load_nm(), default_route_interfaces(self.route_file))

    def find_by_mac(self, mac: str) -> WirelessInterface | None:
        mac = mac.upper()
        for name in self.wireless_names():
            if (self._read(name, "address") or "").upper() == mac:
                return self.interface(name)
        return None

    def _describe(self, name: str, nm: dict[str, str], routes: set[str]) -> WirelessInterface:
        phy = self._phy_name(name)
        bus, usb_id = self._bus_info(name)
        iface = WirelessInterface(
            name=name,
            phy=phy,
            driver=self._driver(name),
            mac=(self._read(name, "address") or "").upper() or None,
            operstate=self._read(name, "operstate"),
            bus=bus,
            usb_id=usb_id,
            nm_state=nm.get(name) if self.nm_running else None,
            default_route=name in routes,
        )
        res = self.runner.run(["iw", "dev", name, "info"])
        if res.ok:
            info = parse_iw_dev_info(res.stdout)
            iface.iftype = info.get("type")
            iface.channel = info.get("channel")
            iface.frequency = info.get("frequency")
            iface.width = info.get("width")
            iface.ssid = info.get("ssid")
        if phy:
            iface.phy_info = self.phy_info(phy)
            iface.regdomain = self.phy_regdomains.get(phy, self.global_regdomain)
        return iface


def capability_effective(status_file: str | Path = "/proc/self/status") -> set[str]:
    """Return the subset of {CAP_NET_ADMIN, CAP_NET_RAW} in the effective set."""
    try:
        text = Path(status_file).read_text()
    except OSError:
        return set()
    m = re.search(r"^CapEff:\s*([0-9a-fA-F]+)$", text, re.M)
    if not m:
        return set()
    caps = int(m.group(1), 16)
    out = set()
    if caps & (1 << 12):
        out.add("CAP_NET_ADMIN")
    if caps & (1 << 13):
        out.add("CAP_NET_RAW")
    return out
