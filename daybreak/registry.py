"""Protected network registry: which BSSIDs/SSIDs the operator administers."""

from __future__ import annotations

import re
from typing import Iterable

from .config import (
    ConfigError, ProtectedNetwork, SecurityExpectation, load_registry_file, save_registry_file,
    validate_network,
)
from .models import AP_OBSERVATION_TYPES, Event, EventType


def _quoted_ssid(ssid: str) -> re.Pattern[str]:
    """The SSID exactly, in single or double quotes, as a whole token of a Kismet alert text."""
    body = re.escape(ssid)
    return re.compile(r"(?<![^\s(\[])(?:'" + body + r"'|\"" + body + r"\")(?=[\s,.;:)\]]|$)")


class NetworkRegistry:
    def __init__(self, networks: Iterable[ProtectedNetwork], *, scope: str = "protected"):
        self.networks = list(networks)
        self.scope = scope
        self._by_bssid: dict[str, ProtectedNetwork] = {}
        self._by_ssid: dict[str, list[ProtectedNetwork]] = {}
        for net in self.networks:
            for b in net.bssids:
                self._by_bssid.setdefault(b, net)
            self._by_ssid.setdefault(net.ssid, []).append(net)
        self._quoted = [(net, _quoted_ssid(net.ssid)) for net in self.networks if net.ssid]

    def by_name(self, name: str) -> ProtectedNetwork | None:
        return next((n for n in self.networks if n.name == name), None)

    def by_bssid(self, bssid: str | None) -> ProtectedNetwork | None:
        return self._by_bssid.get(bssid) if bssid else None

    def by_ssid(self, ssid: str | None) -> list[ProtectedNetwork]:
        return list(self._by_ssid.get(ssid, ())) if ssid else []

    @property
    def protected_bssids(self) -> set[str]:
        return set(self._by_bssid)

    def is_authorized(self, ssid: str | None, bssid: str | None) -> bool | None:
        """True/False for a protected *configured* SSID; None if not applicable."""
        nets = [n for n in self.by_ssid(ssid) if n.configured]
        if not nets:
            return None
        return any(bssid in n.bssids for n in nets)

    def network_of(self, event: Event) -> ProtectedNetwork | None:
        net = self.by_bssid(event.bssid)
        if net:
            return net
        if event.event_type in AP_OBSERVATION_TYPES:
            nets = self.by_ssid(event.ssid)
            return nets[0] if nets else None
        if event.event_type is EventType.KISMET_ALERT:
            for mac in (event.source, event.destination, event.station):
                net = self.by_bssid(mac)
                if net:
                    return net
            # Kismet quotes SSIDs in its alert texts ('...' or "..."): match the whole quoted SSID,
            # never a substring (a neighbour 'myhome-5G' is not the protected network 'home'),
            # and SSIDs that contain quotes themselves ('Bob's WiFi') still match.
            text = str(event.metadata.get("kismet_text", ""))
            for net, pattern in self._quoted:
                if pattern.search(text):
                    return net
        return None

    def in_scope(self, event: Event) -> bool:
        if self.scope == "all" or event.event_type is EventType.SENSOR:
            return True
        if event.event_type in AP_OBSERVATION_TYPES:
            return bool(self.by_ssid(event.ssid)) or event.bssid in self._by_bssid
        if event.event_type is EventType.KISMET_ALERT:
            return self.network_of(event) is not None
        return any(mac in self._by_bssid for mac in (event.bssid, event.source, event.destination))


# ---------------------------------------------------------------------------
# Registry file management (`daybreak-wids network add/remove`)
# ---------------------------------------------------------------------------


class RegistryError(ValueError):
    pass


def add_network(cfg, *, name: str, ssid: str, bssids: Iterable[str] = (), channels: Iterable[int] = (),
                expected: Iterable[str] = (), pmf: str | None = None, replace: bool = False,
                dry_run: bool = False) -> ProtectedNetwork:
    """Add (or with ``replace`` update) a network in the registry file. Returns the network."""
    net = ProtectedNetwork(name=name, ssid=ssid, bssids=list(bssids), channels=list(channels),
                           security=SecurityExpectation(expected=list(expected), pmf=pmf), origin="registry")
    try:
        validate_network(net, f"network {name!r}")
    except ConfigError as exc:
        raise RegistryError(str(exc)) from exc
    existing = cfg.network(name)
    if existing is not None and existing.origin == "config":
        raise RegistryError(f"network {name!r} is defined in {cfg.path or 'the config file'}; edit it there")
    registry = load_registry_file(cfg.registry_path)
    if any(n.name == name for n in registry) and not replace:
        raise RegistryError(f"network {name!r} already exists (use --replace to update it)")
    registry = [n for n in registry if n.name != name] + [net]
    if not dry_run:
        save_registry_file(cfg.registry_path, registry)
    return net


def remove_network(cfg, name: str, *, dry_run: bool = False) -> bool:
    existing = cfg.network(name)
    if existing is not None and existing.origin == "config":
        raise RegistryError(f"network {name!r} is defined in {cfg.path or 'the config file'}; edit it there")
    registry = load_registry_file(cfg.registry_path)
    remaining = [n for n in registry if n.name != name]
    if len(remaining) == len(registry):
        return False
    if not dry_run:
        save_registry_file(cfg.registry_path, remaining)
    return True
