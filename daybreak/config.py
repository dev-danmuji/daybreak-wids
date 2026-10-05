"""Configuration loading and validation (YAML)."""

from __future__ import annotations

import dataclasses
import ipaddress
import os
import types
import typing
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from .fileperm import write_private_atomic
from .models import PMF_LEVELS, Severity, normalize_mac
from .safety import SafetyViolation, enforce_passive, valid_ifname

DEFAULT_SENSOR_INTERFACE = "wlx00c0cab85c32"
DEFAULT_PROTECTED_INTERFACES = ("wlo1",)
CONFIG_ENV = "DAYBREAK_WIDS_CONFIG"
SECURITY_PROTOCOLS = ("OPEN", "WEP", "WPA", "WPA2", "WPA3", "OWE")


class ConfigError(ValueError):
    """Invalid configuration."""


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


@dataclass
class SafetyConfig:
    passive_only: bool = True
    packet_injection: bool = False
    transmit_management_frames: bool = False


@dataclass
class SensorConfig:
    interface: str = DEFAULT_SENSOR_INTERFACE
    expected_driver: str | None = "mt7921u"
    expected_mac: str | None = None
    protected_interfaces: list[str] = field(default_factory=lambda: list(DEFAULT_PROTECTED_INTERFACES))
    health_check_interval: float = 5.0
    # Channels the passive backend listens on. Empty -> protected network channels.
    channels: list[int] = field(default_factory=list)
    dwell_time: float = 0.5
    # Re-apply monitor mode on the *sensor* interface after a USB reset
    # (passive backend only; never touches protected interfaces).
    auto_prepare: bool = True


@dataclass
class KismetConfig:
    url: str = "http://127.0.0.1:2501"
    api_key_env: str = "KISMET_API_KEY"
    username: str | None = None
    password_env: str = "KISMET_PASSWORD"
    poll_interval: float = 2.0
    timeout: float = 5.0
    use_eventbus: bool = True
    # Additionally read per-frame metadata from the monitor interface Kismet opened
    # (receive-only raw socket, needs CAP_NET_RAW). Kismet alone provides WIDS alerts
    # and AP/SSID records but not per-frame deauth/EAPOL metadata.
    frame_tap: bool = True
    datasource_check_interval: float = 10.0


@dataclass
class PassiveConfig:
    # Monitor-mode interface to read from. Defaults to sensor.interface.
    interface: str | None = None


@dataclass
class BackendConfig:
    type: str = "auto"  # auto | kismet | passive | replay
    kismet: KismetConfig = field(default_factory=KismetConfig)
    passive: PassiveConfig = field(default_factory=PassiveConfig)


@dataclass
class SecurityExpectation:
    expected: list[str] = field(default_factory=list)
    pmf: str | None = None


@dataclass
class ProtectedNetwork:
    name: str
    ssid: str
    bssids: list[str] = field(default_factory=list)
    channels: list[int] = field(default_factory=list)
    security: SecurityExpectation = field(default_factory=SecurityExpectation)
    origin: str = "config"  # "config" (config file) or "registry" (managed by CLI)

    @property
    def status(self) -> str:
        return "configured" if self.bssids else "unconfigured"

    @property
    def configured(self) -> bool:
        return bool(self.bssids)

    def to_yaml_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "ssid": self.ssid, "bssids": list(self.bssids)}
        if self.channels:
            out["channels"] = list(self.channels)
        sec: dict[str, Any] = {}
        if self.security.expected:
            sec["expected"] = list(self.security.expected)
        if self.security.pmf:
            sec["pmf"] = self.security.pmf
        if sec:
            out["security"] = sec
        return out


@dataclass
class DeauthConfig:
    burst_threshold: int = 10          # frames ...
    burst_window: float = 5.0          # ... per this many seconds (alert when exceeded)
    broadcast_threshold: int = 3
    broadcast_window: float = 60.0
    multi_client_threshold: int = 3
    multi_client_window: float = 30.0
    rssi_deviation_db: float = 20.0
    suspicious_min_frames: int = 3
    suspicious_window: float = 30.0


@dataclass
class EapolConfig:
    station_window: float = 60.0
    station_handshake_threshold: int = 3   # 4-way handshake starts per station per window
    station_frame_threshold: int = 12      # EAPOL frames per station per window
    bssid_window: float = 60.0
    bssid_frame_threshold: int = 40        # EAPOL frames per BSSID per window
    bssid_station_threshold: int = 4       # stations re-authenticating per BSSID per window


@dataclass
class SpoofConfig:
    enabled: bool = True
    channel_anomaly: bool = True


@dataclass
class CorrelationConfig:
    window: float = 120.0
    reconnect_window: float = 30.0


@dataclass
class BaselineConfig:
    bucket: float = 60.0
    z_threshold: float = 3.0
    min_sigma: float = 0.5
    min_count: int = 5
    default_duration: float = 900.0


@dataclass
class DetectionConfig:
    scope: str = "protected"  # protected | all
    deauth: DeauthConfig = field(default_factory=DeauthConfig)
    eapol: EapolConfig = field(default_factory=EapolConfig)
    spoof: SpoofConfig = field(default_factory=SpoofConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    baseline: BaselineConfig = field(default_factory=BaselineConfig)


DEFAULT_WEIGHTS: dict[str, int] = {
    "deauth_burst": 30,
    "broadcast_deauth": 20,
    "multi_client_deauth": 15,
    "suspicious_source": 15,
    "invalid_reason_code": 5,
    "eapol_reauth_surge": 17,
    "reconnect_after_disconnect": 10,
    "baseline_deviation": 15,
    "unknown_bssid": 30,
    "security_downgrade": 30,
    "encryption_change": 15,
    "pmf_downgrade": 15,
    "channel_anomaly": 10,
    "incompatible_duplicate": 20,
    "concurrent_deauth": 15,
    "kismet_other": 10,
    "sensor_lost": 50,
    "protected_interface_changed": 50,
}


@dataclass
class ScoringConfig:
    weights: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))

    def weight(self, name: str) -> int:
        return int(self.weights.get(name, DEFAULT_WEIGHTS.get(name, 0)))


@dataclass
class NotifierConfig:
    type: str
    min_severity: str = "LOW"
    options: dict[str, Any] = field(default_factory=dict)


def _default_notifiers() -> list[NotifierConfig]:
    return [
        NotifierConfig(type="console", min_severity="LOW"),
        NotifierConfig(type="jsonl", min_severity="INFO"),
        NotifierConfig(type="desktop", min_severity="HIGH"),
    ]


@dataclass
class AlertsConfig:
    cooldown: float = 300.0
    escalation_delta: int = 10
    rate_limit_per_minute: int = 20
    notifiers: list[NotifierConfig] = field(default_factory=_default_notifiers)


@dataclass
class StorageConfig:
    database: str = "daybreak.db"
    retention_days: int = 30


@dataclass
class LoggingConfig:
    directory: str = "log"
    human_log: str = "daybreak.log"
    jsonl_log: str = "alerts.jsonl"
    max_bytes: int = 10 * 1024 * 1024
    backup_count: int = 5
    level: str = "INFO"


@dataclass
class DashboardConfig:
    host: str = "127.0.0.1"
    port: int = 8765
    allow_remote: bool = False
    # Extra Host-header names accepted with allow_remote (the names/addresses typed in the browser).
    allowed_hosts: list[str] = field(default_factory=list)


@dataclass
class Config:
    sensor: SensorConfig = field(default_factory=SensorConfig)
    backend: BackendConfig = field(default_factory=BackendConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    protected_networks: list[ProtectedNetwork] = field(default_factory=list)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    registry_file: str = "networks.yaml"
    # Not configurable: where the config was loaded from and the base for relative paths.
    path: Path | None = None
    base_dir: Path = field(default_factory=Path.cwd)

    # -- resolved paths ------------------------------------------------------
    def resolve(self, value: str | Path) -> Path:
        p = Path(os.path.expanduser(str(value)))
        return p if p.is_absolute() else (self.base_dir / p)

    @property
    def database_path(self) -> Path:
        return self.resolve(self.storage.database)

    @property
    def log_dir(self) -> Path:
        return self.resolve(self.logging.directory)

    @property
    def registry_path(self) -> Path:
        return self.resolve(self.registry_file)

    @property
    def state_dir(self) -> Path:
        return self.database_path.parent

    def network(self, name: str) -> ProtectedNetwork | None:
        return next((n for n in self.protected_networks if n.name == name), None)


# ---------------------------------------------------------------------------
# Generic strict dataclass builder
# ---------------------------------------------------------------------------

_NOT_USER_SETTABLE = {"path", "base_dir", "origin"}


def _build(cls: type, data: Any, where: str) -> Any:
    if data is None:
        data = {}
    if not isinstance(data, Mapping):
        raise ConfigError(f"{where or 'config'}: expected a mapping, got {type(data).__name__}")
    hints = typing.get_type_hints(cls)
    known = {f.name: f for f in dataclasses.fields(cls) if f.name not in _NOT_USER_SETTABLE}
    kwargs: dict[str, Any] = {}
    for key, value in data.items():
        if key not in known:
            raise ConfigError(f"unknown option: {where + '.' if where else ''}{key}")
        kwargs[key] = _coerce(hints[key], value, f"{where + '.' if where else ''}{key}")
    try:
        return cls(**kwargs)
    except TypeError as exc:
        raise ConfigError(f"{where or 'config'}: {exc}") from exc


def _coerce(tp: Any, value: Any, where: str) -> Any:
    origin = typing.get_origin(tp)
    args = typing.get_args(tp)
    if origin is typing.Union or origin is types.UnionType:
        non_none = [a for a in args if a is not type(None)]
        if value is None:
            return None
        return _coerce(non_none[0], value, where)
    if dataclasses.is_dataclass(tp):
        return _build(tp, value, where)
    if origin is list:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ConfigError(f"{where}: expected a list")
        return [_coerce(args[0] if args else Any, v, f"{where}[{i}]") for i, v in enumerate(value)]
    if origin is dict:
        if value is None:
            return {}
        if not isinstance(value, Mapping):
            raise ConfigError(f"{where}: expected a mapping")
        return dict(value)
    if tp is bool:
        if not isinstance(value, bool):
            raise ConfigError(f"{where}: expected true/false, got {value!r}")
        return value
    if tp is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{where}: expected an integer, got {value!r}")
        return value
    if tp is float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{where}: expected a number, got {value!r}")
        return float(value)
    if tp is str:
        if not isinstance(value, (str, int, float)) or isinstance(value, bool):
            raise ConfigError(f"{where}: expected a string, got {value!r}")
        return str(value)
    return value


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def parse_network(data: Any, where: str, origin: str = "config") -> ProtectedNetwork:
    if not isinstance(data, Mapping):
        raise ConfigError(f"{where}: expected a mapping")
    if "name" not in data or "ssid" not in data:
        raise ConfigError(f"{where}: 'name' and 'ssid' are required")
    net = _build(ProtectedNetwork, data, where)
    net.origin = origin
    validate_network(net, where)
    return net


def validate_network(net: ProtectedNetwork, where: str) -> None:
    if not net.name or not str(net.name).strip():
        raise ConfigError(f"{where}.name must not be empty")
    if not net.ssid:
        raise ConfigError(f"{where}.ssid must not be empty")
    if len(net.ssid.encode("utf-8")) > 32:
        raise ConfigError(f"{where}.ssid is longer than 32 octets")
    bssids = []
    for i, b in enumerate(net.bssids):
        try:
            mac = normalize_mac(b)
        except ValueError as exc:
            raise ConfigError(f"{where}.bssids[{i}]: {exc}") from exc
        if mac not in bssids:
            bssids.append(mac)
    net.bssids = bssids
    for ch in net.channels:
        if not 1 <= ch <= 233:
            raise ConfigError(f"{where}.channels: invalid channel {ch}")
    expected = [str(e).upper() for e in net.security.expected]
    for e in expected:
        if e not in SECURITY_PROTOCOLS:
            raise ConfigError(f"{where}.security.expected: unknown protocol {e!r} "
                              f"(use {', '.join(SECURITY_PROTOCOLS)})")
    net.security.expected = expected
    if net.security.pmf is not None:
        pmf = net.security.pmf.lower()
        if pmf not in PMF_LEVELS:
            raise ConfigError(f"{where}.security.pmf must be one of {', '.join(PMF_LEVELS)}")
        net.security.pmf = pmf


def _validate_kismet_url(url: str) -> None:
    """http(s)://host[:port][/path] only. The URL ends up in error messages and status files,
    so it must never carry credentials (the messages below never echo it)."""
    try:
        parts = urllib.parse.urlsplit(url)
        parts.port  # noqa: B018 - raises ValueError for an invalid port
    except ValueError as exc:
        raise ConfigError("backend.kismet.url is not a valid URL") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError("backend.kismet.url must be an http(s) URL with a host, e.g. http://127.0.0.1:2501")
    if "@" in parts.netloc or parts.query or parts.fragment or "@" in parts.path:
        raise ConfigError("backend.kismet.url must not contain credentials, a query or a fragment; use "
                          "backend.kismet.api_key_env (or username + password_env)")


def is_loopback_host(host: str) -> bool:
    """True for localhost and loopback addresses (IPv6 with or without brackets)."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _validate(cfg: Config) -> None:
    enforce_passive(cfg.safety)
    if not cfg.sensor.interface:
        raise ConfigError("sensor.interface must be set")
    names = [("sensor.interface", cfg.sensor.interface), ("backend.passive.interface", cfg.backend.passive.interface)]
    names += [(f"sensor.protected_interfaces[{i}]", n) for i, n in enumerate(cfg.sensor.protected_interfaces)]
    for where, name in names:
        if name is not None and not valid_ifname(name):
            raise ConfigError(f"{where}: {name!r} is not a valid interface name")
    for ch in cfg.sensor.channels:
        if not 1 <= ch <= 233:
            raise ConfigError(f"sensor.channels: invalid channel {ch}")
    for key in ("dwell_time", "health_check_interval"):
        if getattr(cfg.sensor, key) <= 0:
            raise ConfigError(f"sensor.{key} must be positive")
    if cfg.sensor.interface in cfg.sensor.protected_interfaces:
        raise ConfigError(
            f"sensor.interface {cfg.sensor.interface!r} is listed in sensor.protected_interfaces; "
            "the sensor must be a dedicated adapter"
        )
    if cfg.sensor.expected_mac:
        try:
            cfg.sensor.expected_mac = normalize_mac(cfg.sensor.expected_mac)
        except ValueError as exc:
            raise ConfigError(f"sensor.expected_mac: {exc}") from exc
    if cfg.backend.type not in ("auto", "kismet", "passive", "replay"):
        raise ConfigError("backend.type must be auto, kismet, passive or replay")
    if cfg.backend.passive.interface and cfg.backend.passive.interface in cfg.sensor.protected_interfaces:
        raise ConfigError("backend.passive.interface must not be a protected interface")
    if cfg.detection.scope not in ("protected", "all"):
        raise ConfigError("detection.scope must be 'protected' or 'all'")
    for name, section in (("detection.deauth", cfg.detection.deauth),
                          ("detection.eapol", cfg.detection.eapol),
                          ("detection.correlation", cfg.detection.correlation),
                          ("detection.baseline", cfg.detection.baseline)):
        for f in dataclasses.fields(section):
            value = getattr(section, f.name)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and value <= 0:
                raise ConfigError(f"{name}.{f.name} must be positive")
    for i, n in enumerate(cfg.alerts.notifiers):
        try:
            n.min_severity = Severity.parse(n.min_severity).name
        except ValueError as exc:
            raise ConfigError(f"alerts.notifiers[{i}].min_severity: {exc}") from exc
    if cfg.alerts.cooldown < 0:
        raise ConfigError("alerts.cooldown must be >= 0")
    for key, value in cfg.scoring.weights.items():
        if key not in DEFAULT_WEIGHTS:
            raise ConfigError(f"unknown scoring weight: {key} (known: {', '.join(sorted(DEFAULT_WEIGHTS))})")
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
            raise ConfigError(f"scoring.weights.{key} must be an integer 0-100")
    if cfg.storage.retention_days < 0:
        raise ConfigError("storage.retention_days must be >= 0 (0 keeps data forever)")
    _validate_kismet_url(cfg.backend.kismet.url)
    if not is_loopback_host(cfg.dashboard.host) and not cfg.dashboard.allow_remote:
        raise ConfigError("dashboard.host must be a loopback address unless dashboard.allow_remote is true")
    for host in cfg.dashboard.allowed_hosts:
        if not isinstance(host, str) or not host.strip() or any(c in host for c in " /@"):
            raise ConfigError(f"dashboard.allowed_hosts: invalid host name {host!r}")
    names = [n.name for n in cfg.protected_networks]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        raise ConfigError(f"duplicate protected network name(s): {', '.join(sorted(dupes))}")


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def default_config_candidates() -> list[Path]:
    out = []
    env = os.environ.get(CONFIG_ENV)
    if env:
        out.append(Path(env))
    out.append(Path.cwd() / "config.yaml")
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    out.append(Path(xdg) / "daybreak-wids" / "config.yaml")
    return out


def _default_base_dir() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return Path(xdg) / "daybreak-wids"


def config_from_dict(data: Mapping[str, Any] | None, *, base_dir: Path | None = None,
                     path: Path | None = None, load_registry: bool = True) -> Config:
    data = dict(data or {})
    networks_raw = data.pop("protected_networks", None) or []
    if not isinstance(networks_raw, list):
        raise ConfigError("protected_networks must be a list")
    try:
        cfg: Config = _build(Config, data, "")
    except SafetyViolation:
        raise
    cfg.path = path
    cfg.base_dir = base_dir or (path.parent if path else _default_base_dir())
    cfg.protected_networks = [parse_network(n, f"protected_networks[{i}]")
                              for i, n in enumerate(networks_raw)]
    if load_registry:
        cfg.protected_networks.extend(load_registry_file(cfg.registry_path))
    _validate(cfg)
    return cfg


def load_registry_file(path: Path) -> list[ProtectedNetwork]:
    """Networks added with ``daybreak-wids network add`` live in a separate file."""
    if not path.exists():
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    items = raw.get("protected_networks", []) if isinstance(raw, Mapping) else None
    if not isinstance(items, list):
        raise ConfigError(f"{path}: expected 'protected_networks: [...]'")
    return [parse_network(n, f"{path.name}:protected_networks[{i}]", origin="registry")
            for i, n in enumerate(items)]


def save_registry_file(path: Path, networks: list[ProtectedNetwork]) -> None:
    doc = {"protected_networks": [n.to_yaml_dict() for n in networks if n.origin == "registry"]}
    header = ("# Managed by `daybreak-wids network add/remove`.\n"
              "# Networks defined in config.yaml are not listed here.\n")
    write_private_atomic(path, header + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True))


def load_config(path: str | Path | None = None) -> Config:
    """Load configuration from ``path`` or the first default location that exists."""
    if path is not None:
        p = Path(path).expanduser()
        if not p.exists():
            raise ConfigError(f"config file not found: {p}")
        candidates = [p]
    else:
        candidates = [c for c in default_config_candidates() if c.exists()]
    if not candidates:
        return config_from_dict({}, base_dir=_default_base_dir())
    p = candidates[0].resolve()
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{p}: invalid YAML: {exc}") from exc
    if not isinstance(data, Mapping):
        raise ConfigError(f"{p}: top level must be a mapping")
    return config_from_dict(data, path=p)
