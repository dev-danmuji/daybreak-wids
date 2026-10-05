"""Core data model: MAC helpers, events, findings, alerts, security profiles.

Events only ever carry *metadata* (addresses, timing, reason codes, counters).
Anything that could help an attacker (EAPOL nonces/MICs, PMKIDs, key data,
raw frames, passphrases) is stripped by :func:`sanitize_metadata` before an
event can be stored or logged.
"""

from __future__ import annotations

import enum
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

# ---------------------------------------------------------------------------
# MAC addresses
# ---------------------------------------------------------------------------

BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"

_HEX12 = re.compile(r"^[0-9A-Fa-f]{12}$")


def normalize_mac(value: Any) -> str:
    """Return ``value`` as an upper-case, colon separated MAC address.

    Accepts ``aa:bb:cc:dd:ee:ff``, ``AA-BB-CC-DD-EE-FF``, ``aabb.ccdd.eeff``,
    ``aabbccddeeff`` and 6-byte ``bytes``. Raises :class:`ValueError` otherwise.
    """
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) != 6:
            raise ValueError(f"MAC address must be 6 bytes, got {len(raw)}")
        return ":".join(f"{b:02X}" for b in raw)
    if not isinstance(value, str):
        raise ValueError(f"MAC address must be a string, got {type(value).__name__}")
    text = value.strip()
    if ":" in text or "-" in text:
        parts = re.split(r"[:\-]", text)
        if len(parts) != 6 or not all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", p) for p in parts):
            raise ValueError(f"invalid MAC address: {value!r}")
        return ":".join(p.zfill(2).upper() for p in parts)
    compact = text.replace(".", "")
    if not _HEX12.match(compact):
        raise ValueError(f"invalid MAC address: {value!r}")
    compact = compact.upper()
    return ":".join(compact[i:i + 2] for i in range(0, 12, 2))


def try_normalize_mac(value: Any) -> str | None:
    """Like :func:`normalize_mac` but returns ``None`` for empty/invalid input."""
    if value in (None, ""):
        return None
    try:
        return normalize_mac(value)
    except ValueError:
        return None


def is_group_address(mac: str | None) -> bool:
    """True for broadcast/multicast (group) addresses (I/G bit set)."""
    if not mac:
        return False
    return bool(int(mac[0:2], 16) & 0x01)


def is_locally_administered(mac: str | None) -> bool:
    """True for locally administered (often randomized) addresses."""
    if not mac:
        return False
    return bool(int(mac[0:2], 16) & 0x02)


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------


# Upper bound for event timestamps (2100-01-01): later values come from broken or crafted
# input and would break date formatting and time-bucketed statistics.
MAX_EVENT_TS = 4_102_444_800.0


def plausible_timestamp(ts: float) -> bool:
    return math.isfinite(ts) and 0 < ts <= MAX_EVENT_TS


def clean_text(value: str) -> str:
    """``value`` encodable as UTF-8 (lone surrogates from JSON escapes become '?')."""
    try:
        value.encode("utf-8")
        return value
    except UnicodeEncodeError:
        return value.encode("utf-8", "replace").decode("utf-8")


def parse_timestamp(value: Any) -> float:
    """Parse epoch seconds (int/float/numeric str) or an ISO-8601 string."""
    if isinstance(value, bool):
        raise ValueError("timestamp must not be a boolean")
    if isinstance(value, (int, float)):
        try:
            ts = float(value)
        except OverflowError as exc:
            raise ValueError("timestamp out of range") from exc
    elif isinstance(value, str):
        text = value.strip()
        try:
            ts = float(text)
        except ValueError:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(text)
            except ValueError as exc:
                raise ValueError(f"invalid timestamp: {value!r}") from exc
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ts = dt.timestamp()
    else:
        raise ValueError(f"invalid timestamp type: {type(value).__name__}")
    if not plausible_timestamp(ts):
        raise ValueError(f"timestamp out of range: {str(value)[:40]!r}")
    return ts


def iso_utc(ts: float) -> str:
    """Epoch seconds -> ``2026-10-05T06:31:11.123Z`` (``invalid-time`` for unrepresentable values)."""
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    except (OverflowError, OSError, ValueError, TypeError):
        return "invalid-time"
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def format_local(ts: float) -> str:
    """Epoch seconds -> local ``2026-10-05 15:31:11`` (``invalid-time`` for unrepresentable values)."""
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError, TypeError):
        return "invalid-time"


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Risk score bands: 0-29 INFO, 30-49 LOW, 50-69 MEDIUM, 70-89 HIGH, 90-100 CRITICAL."""
        if score >= 90:
            return cls.CRITICAL
        if score >= 70:
            return cls.HIGH
        if score >= 50:
            return cls.MEDIUM
        if score >= 30:
            return cls.LOW
        return cls.INFO

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            return cls(value)
        if isinstance(value, str) and value.strip().upper() in cls.__members__:
            return cls[value.strip().upper()]
        raise ValueError(f"unknown severity: {value!r}")


# ---------------------------------------------------------------------------
# Security profile (filled by daybreak.dot11.rsn or the Kismet adapter)
# ---------------------------------------------------------------------------

SAE_AKMS = frozenset({"SAE", "FT-SAE", "SAE-EXT-KEY", "FT-SAE-EXT-KEY"})
PSK_AKMS = frozenset({"PSK", "FT-PSK", "PSK-SHA256", "PSK-SHA384", "FT-PSK-SHA384"})
ENTERPRISE_AKMS = frozenset({
    "802.1X", "FT-802.1X", "802.1X-SHA256", "802.1X-SUITE-B", "802.1X-SUITE-B-192",
    "FT-802.1X-SHA384", "802.1X-SHA384",
})
OWE_AKMS = frozenset({"OWE"})

PMF_LEVELS = ("disabled", "capable", "required")


@dataclass(frozen=True)
class SecurityProfile:
    """Security capabilities advertised by an AP (beacon/probe response)."""

    privacy: bool = False
    rsn: bool = False
    wpa1: bool = False
    akms: tuple[str, ...] = ()
    pairwise_ciphers: tuple[str, ...] = ()
    group_cipher: str | None = None
    group_mgmt_cipher: str | None = None
    mfp_capable: bool = False
    mfp_required: bool = False
    sae_h2e: bool | None = None
    wps: bool | None = None
    source: str = "ie"  # "ie" (parsed elements) or "kismet" (crypt_string)

    # -- derived ----------------------------------------------------------
    @property
    def has_sae(self) -> bool:
        return any(a in SAE_AKMS for a in self.akms)

    @property
    def has_psk(self) -> bool:
        return any(a in PSK_AKMS for a in self.akms)

    @property
    def has_enterprise(self) -> bool:
        return any(a in ENTERPRISE_AKMS for a in self.akms)

    @property
    def has_owe(self) -> bool:
        return any(a in OWE_AKMS for a in self.akms)

    @property
    def protocols(self) -> frozenset[str]:
        """Coarse protocol set used for comparisons: OPEN/WEP/WPA/WPA2/WPA3/OWE."""
        if not self.privacy and not self.rsn and not self.wpa1:
            return frozenset({"OPEN"})
        out: set[str] = set()
        if self.wpa1:
            out.add("WPA")
        if self.rsn:
            if self.has_sae:
                out.add("WPA3")
            if self.has_psk:
                out.add("WPA2")
            if self.has_enterprise:
                if "802.1X-SUITE-B-192" in self.akms or (
                    self.mfp_required and not self.has_psk
                    and any(a in {"802.1X-SHA256", "802.1X-SUITE-B", "802.1X-SHA384"} for a in self.akms)
                ):
                    out.add("WPA3")
                else:
                    out.add("WPA2")
            if self.has_owe:
                out.add("OWE")
            if not out:
                out.add("WPA2")  # RSN with unknown AKMs
        if not out:
            out.add("WEP")
        return frozenset(out)

    @property
    def transition_mode(self) -> bool:
        return self.has_sae and self.has_psk

    @property
    def mode(self) -> str:
        protos = self.protocols
        if protos == {"OPEN"}:
            return "OPEN"
        if protos == {"WEP"}:
            return "WEP"
        if self.has_enterprise and not (self.has_sae or self.has_psk):
            return "WPA3-ENTERPRISE" if "WPA3" in protos else "WPA2-ENTERPRISE"
        if self.transition_mode:
            return "WPA2/WPA3-TRANSITION"
        if "WPA3" in protos:
            return "WPA3-SAE"
        if "OWE" in protos and len(protos) == 1:
            return "OWE"
        if "WPA2" in protos and "WPA" in protos:
            return "WPA/WPA2-MIXED"
        if "WPA2" in protos:
            return "WPA2-PSK"
        if "WPA" in protos:
            return "WPA"
        return "/".join(sorted(protos))

    @property
    def pmf(self) -> str:
        if self.mfp_required:
            return "required"
        if self.mfp_capable:
            return "capable"
        return "disabled"

    @property
    def pmf_rank(self) -> int:
        return PMF_LEVELS.index(self.pmf)

    @property
    def rank(self) -> int:
        """Strength rank for downgrade detection (higher is stronger)."""
        mode = self.mode
        return {
            "OPEN": 0,
            "WEP": 1,
            "OWE": 2,
            "WPA": 2,
            "WPA/WPA2-MIXED": 2,
            "WPA2-PSK": 3,
            "WPA2-ENTERPRISE": 4,
            "WPA2/WPA3-TRANSITION": 4,
            "WPA3-SAE": 5,
            "WPA3-ENTERPRISE": 5,
        }.get(mode, 3)

    def signature(self) -> tuple:
        """Comparison key that ignores fields only one source (IE parsing vs Kismet) reports."""
        return (self.mode, self.pmf, tuple(sorted(self.akms)))

    def same_capabilities(self, other: "SecurityProfile | None") -> bool:
        if other is None:
            return False
        if self.signature() != other.signature():
            return False
        if self.source == other.source == "ie":
            return (set(self.pairwise_ciphers) == set(other.pairwise_ciphers)
                    and self.group_cipher == other.group_cipher)
        return True

    @property
    def weak_ciphers(self) -> tuple[str, ...]:
        weak = {"TKIP", "WEP40", "WEP104", "WEP"}
        found = [c for c in self.pairwise_ciphers if c in weak]
        if self.group_cipher in weak:
            found.append(self.group_cipher)
        return tuple(sorted(set(found)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "privacy": self.privacy,
            "rsn": self.rsn,
            "wpa1": self.wpa1,
            "akms": list(self.akms),
            "pairwise_ciphers": list(self.pairwise_ciphers),
            "group_cipher": self.group_cipher,
            "group_mgmt_cipher": self.group_mgmt_cipher,
            "mfp_capable": self.mfp_capable,
            "mfp_required": self.mfp_required,
            "sae_h2e": self.sae_h2e,
            "wps": self.wps,
            "source": self.source,
            "mode": self.mode,
            "pmf": self.pmf,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SecurityProfile":
        if not isinstance(data, Mapping):
            raise ValueError("security must be an object")

        def _tuple(key: str) -> tuple[str, ...]:
            value = data.get(key) or ()
            if isinstance(value, str):
                value = [value]
            if not isinstance(value, (list, tuple)):
                raise ValueError(f"security.{key} must be a list")
            return tuple(str(v).upper() for v in value)

        def _opt_bool(key: str) -> bool | None:
            value = data.get(key)
            return None if value is None else bool(value)

        mfp_required = bool(data.get("mfp_required", False))
        pmf = data.get("pmf")
        mfp_capable = bool(data.get("mfp_capable", False))
        if isinstance(pmf, str):
            pmf = pmf.lower()
            if pmf not in PMF_LEVELS:
                raise ValueError(f"unknown pmf level: {pmf!r}")
            mfp_required = pmf == "required"
            mfp_capable = pmf in ("capable", "required")
        akms = _tuple("akms")
        rsn = bool(data.get("rsn", bool(akms)))
        return cls(
            privacy=bool(data.get("privacy", rsn or bool(data.get("wpa1")))),
            rsn=rsn,
            wpa1=bool(data.get("wpa1", False)),
            akms=akms,
            pairwise_ciphers=_tuple("pairwise_ciphers"),
            group_cipher=(str(data["group_cipher"]).upper() if data.get("group_cipher") else None),
            group_mgmt_cipher=(str(data["group_mgmt_cipher"]).upper() if data.get("group_mgmt_cipher") else None),
            mfp_capable=mfp_capable or mfp_required,
            mfp_required=mfp_required,
            sae_h2e=_opt_bool("sae_h2e"),
            wps=_opt_bool("wps"),
            source=str(data.get("source", "ie")),
        )


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


class EventType(str, enum.Enum):
    DEAUTH = "deauth"
    DISASSOC = "disassoc"
    AUTH = "auth"
    ASSOC = "assoc"
    REASSOC = "reassoc"
    EAPOL = "eapol"
    BEACON = "beacon"
    PROBE_RESP = "probe_resp"
    KISMET_ALERT = "kismet_alert"
    SENSOR = "sensor"

    @classmethod
    def parse(cls, value: Any) -> "EventType":
        if isinstance(value, EventType):
            return value
        if not isinstance(value, str):
            raise ValueError(f"event type must be a string, got {type(value).__name__}")
        key = value.strip().lower().replace("-", "_")
        key = _EVENT_ALIASES.get(key, key)
        try:
            return cls(key)
        except ValueError as exc:
            raise ValueError(f"unknown event type: {value!r}") from exc


_EVENT_ALIASES = {
    "deauthentication": "deauth",
    "disassociation": "disassoc",
    "authentication": "auth",
    "association": "assoc",
    "assoc_req": "assoc",
    "assoc_resp": "assoc",
    "reassociation": "reassoc",
    "reassoc_req": "reassoc",
    "reassoc_resp": "reassoc",
    "probe_response": "probe_resp",
    "proberesp": "probe_resp",
    "alert": "kismet_alert",
}

DISCONNECT_TYPES = frozenset({EventType.DEAUTH, EventType.DISASSOC})
CONNECT_TYPES = frozenset({EventType.AUTH, EventType.ASSOC, EventType.REASSOC})
AP_OBSERVATION_TYPES = frozenset({EventType.BEACON, EventType.PROBE_RESP})


class MalformedEventError(ValueError):
    """An input event could not be validated."""


# Metadata keys that may be persisted. Everything else is dropped.
ALLOWED_METADATA_KEYS = frozenset({
    "seq", "retry", "subtype", "frame_protection", "malformed",
    "eapol_type", "eapol_msg", "eap_code",
    "auth_alg", "auth_seq", "status_code",
    "frequency", "beacon_interval", "phy", "hidden", "wps_state",
    "kismet_header", "kismet_class", "kismet_severity", "kismet_text", "kismet_hash",
    "count", "num_clients", "source_backend", "note",
    "status", "interface", "mac", "reason", "datasource",
})

# Keys that must never be persisted, even if a backend hands them to us.
SENSITIVE_METADATA_KEYS = frozenset({
    "nonce", "anonce", "snonce", "mic", "key_mic", "key_data", "keydata", "key_iv",
    "key_rsc", "key_nonce", "replay_counter", "pmkid", "pmk", "ptk", "gtk", "kck", "kek",
    "psk", "passphrase", "password", "secret", "handshake", "eapol_frame",
    "eapol_payload", "payload", "raw", "raw_frame", "frame", "frame_bytes", "packet",
    "pcap", "eap_identity", "identity", "username",
})

_MAX_TEXT = 512


_PHY_KEYS = frozenset({"ht", "vht", "he", "eht"})


def _sanitize_value(key: str, value: Any) -> Any:
    """Scalars only. ``phy`` is the one structured key, with a fixed schema of booleans:
    mappings and lists cannot smuggle key material under an allowed key."""
    if key == "phy":
        if isinstance(value, Mapping):
            clean = {k: v for k, v in value.items() if k in _PHY_KEYS and isinstance(v, bool)}
            return clean or None
        return None
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return clean_text(value[:_MAX_TEXT])
    return None  # bytes, mappings, lists and anything else are never persisted


def sanitize_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    """Allow-list filter for event metadata (see module docstring)."""
    if not metadata:
        return {}
    out: dict[str, Any] = {}
    for key, value in metadata.items():
        k = str(key)
        if k.lower() in SENSITIVE_METADATA_KEYS or k not in ALLOWED_METADATA_KEYS:
            continue
        clean = _sanitize_value(k, value)
        if clean is not None:
            out[k] = clean
    return out


_FIELD_ALIASES = {
    "ts": "timestamp", "time": "timestamp",
    "type": "event_type", "event": "event_type",
    "src": "source", "sa": "source", "transmitter": "source", "ta": "source",
    "dst": "destination", "da": "destination", "receiver": "destination", "ra": "destination",
    "client": "station", "sta": "station",
    "signal": "rssi", "dbm": "rssi",
    "reason": "reason_code",
    "meta": "metadata",
}

_EVENT_FIELDS = frozenset({
    "timestamp", "event_type", "sensor", "bssid", "source", "destination", "station",
    "channel", "rssi", "reason_code", "protected", "ssid", "security", "metadata", "id",
})


@dataclass(slots=True)
class Event:
    timestamp: float
    event_type: EventType
    sensor: str = ""
    bssid: str | None = None
    source: str | None = None
    destination: str | None = None
    station: str | None = None
    channel: int | None = None
    rssi: int | None = None
    reason_code: int | None = None
    protected: bool | None = None
    ssid: str | None = None
    security: SecurityProfile | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # -- derived ------------------------------------------------------------
    @property
    def broadcast(self) -> bool:
        return is_group_address(self.destination)

    @property
    def is_disconnect(self) -> bool:
        return self.event_type in DISCONNECT_TYPES

    def derive_station(self) -> None:
        """Fill ``station`` from source/destination relative to the BSSID."""
        if self.station or not self.bssid:
            return
        if self.source == self.bssid and self.destination and not is_group_address(self.destination):
            self.station = self.destination
        elif self.destination == self.bssid and self.source and not is_group_address(self.source):
            self.station = self.source

    def fingerprint(self) -> str:
        """Stable identity used for duplicate suppression."""
        md = self.metadata
        key = (
            self.event_type.value, round(self.timestamp, 3), self.bssid, self.source,
            self.destination, self.station, self.reason_code, self.channel,
            md.get("seq"), md.get("eapol_msg"), md.get("kismet_hash"), md.get("kismet_header"),
            self.ssid,
        )
        return hashlib.sha1(repr(key).encode()).hexdigest()

    # -- (de)serialisation ------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "timestamp": iso_utc(self.timestamp),
            "event_type": self.event_type.value,
        }
        for name in ("sensor", "bssid", "source", "destination", "station", "channel",
                     "rssi", "reason_code", "protected", "ssid"):
            value = getattr(self, name)
            if value not in (None, ""):
                out[name] = value
        if self.security is not None:
            out["security"] = self.security.to_dict()
        if self.metadata:
            out["metadata"] = sanitize_metadata(self.metadata)
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, default_sensor: str = "") -> "Event":
        if not isinstance(data, Mapping):
            raise MalformedEventError("event must be a JSON object")
        fields: dict[str, Any] = {}
        extra: dict[str, Any] = {}
        for raw_key, value in data.items():
            key = _FIELD_ALIASES.get(str(raw_key).lower(), str(raw_key).lower())
            if key in _EVENT_FIELDS:
                fields[key] = value
            else:
                extra[str(raw_key)] = value
        try:
            if "timestamp" not in fields:
                raise ValueError("missing timestamp")
            if "event_type" not in fields:
                raise ValueError("missing event type")
            ts = parse_timestamp(fields["timestamp"])
            etype = EventType.parse(fields["event_type"])
            macs = {}
            for name in ("bssid", "source", "destination", "station"):
                value = fields.get(name)
                macs[name] = None if value in (None, "") else normalize_mac(value)
            channel = _opt_int(fields.get("channel"), "channel", 1, 233)
            rssi = _opt_int(fields.get("rssi"), "rssi", -127, 30, clamp_none=True)
            reason = _opt_int(fields.get("reason_code"), "reason_code", 0, 65535)
            protected = fields.get("protected")
            if protected is not None and not isinstance(protected, bool):
                raise ValueError("protected must be a boolean")
            ssid = fields.get("ssid")
            if ssid is not None:
                if not isinstance(ssid, str):
                    raise ValueError("ssid must be a string")
                if len(ssid.encode("utf-8")) > 32:
                    raise ValueError("ssid longer than 32 octets")
            security = fields.get("security")
            profile = SecurityProfile.from_dict(security) if security is not None else None
            metadata = fields.get("metadata") or {}
            if not isinstance(metadata, Mapping):
                raise ValueError("metadata must be an object")
            merged = dict(extra)
            merged.update(metadata)
            sensor = fields.get("sensor") or default_sensor
            if not isinstance(sensor, str):
                raise ValueError("sensor must be a string")
            sensor = clean_text(sensor)[:64]
            if ssid is not None:
                ssid = clean_text(ssid)
        except (ValueError, TypeError, OverflowError) as exc:
            raise MalformedEventError(str(exc)[:200]) from exc
        event = cls(
            timestamp=ts,
            event_type=etype,
            sensor=sensor,
            bssid=macs["bssid"],
            source=macs["source"],
            destination=macs["destination"],
            station=macs["station"],
            channel=channel,
            rssi=rssi,
            reason_code=reason,
            protected=protected,
            ssid=ssid,
            security=profile,
            metadata=sanitize_metadata(merged),
        )
        event.derive_station()
        return event

    @classmethod
    def from_json(cls, line: str, *, default_sensor: str = "") -> "Event":
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise MalformedEventError(f"invalid JSON: {exc.msg}") from exc
        except (ValueError, RecursionError) as exc:  # oversized numbers, absurd nesting
            raise MalformedEventError(f"invalid JSON: {type(exc).__name__}") from exc
        return cls.from_dict(data, default_sensor=default_sensor)


def _opt_int(value: Any, name: str, lo: int, hi: int, *, clamp_none: bool = False) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if isinstance(value, float):
        if not value.is_integer():
            if clamp_none:
                value = round(value)
            else:
                raise ValueError(f"{name} must be an integer")
        value = int(value)
    if isinstance(value, str):
        value = int(value.strip())
    if not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not lo <= value <= hi:
        if clamp_none:
            return None
        raise ValueError(f"{name} out of range: {value}")
    return value


# ---------------------------------------------------------------------------
# Findings and alerts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScoreComponent:
    points: int
    label: str
    detail: str = ""
    category: str = ""

    def render(self) -> str:
        sign = "+" if self.points >= 0 else ""
        text = f"{sign}{self.points} {self.label}"
        return f"{text} ({self.detail})" if self.detail else text

    def to_dict(self) -> dict[str, Any]:
        return {"points": self.points, "label": self.label, "detail": self.detail,
                "category": self.category}


@dataclass
class Finding:
    """A single detector observation. Several findings correlate into alerts."""

    finding_type: str
    timestamp: float
    category: str
    points: int
    label: str
    detail: str = ""
    bssid: str | None = None
    network: str | None = None
    ssid: str | None = None
    channel: int | None = None
    stations: frozenset[str] = frozenset()
    details: dict[str, Any] = field(default_factory=dict)
    source: str = "daybreak"

    def component(self) -> ScoreComponent:
        return ScoreComponent(self.points, self.label, self.detail, self.category)


@dataclass
class Alert:
    alert_type: str
    timestamp: float
    score: int
    components: list[ScoreComponent]
    summary: str = ""
    network: str | None = None
    network_id: int | None = None
    bssid: str | None = None
    ssid: str | None = None
    channel: int | None = None
    sensor: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    stations: tuple[str, ...] = ()
    id: int | None = None
    acknowledged: bool = False
    suppressed_count: int = 0

    def __post_init__(self) -> None:
        self.score = max(0, min(100, int(round(self.score))))

    @property
    def severity(self) -> Severity:
        return Severity.from_score(self.score)

    @property
    def dedup_key(self) -> tuple[str, str]:
        scope = self.network or self.bssid or self.ssid or self.sensor or "-"
        return (self.alert_type, scope)

    def score_lines(self) -> list[str]:
        return [c.render() for c in self.components]

    def reason_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "components": [c.to_dict() for c in self.components],
            "details": self.details,
            "stations": list(self.stations),
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "network": self.network,
            "sensor": self.sensor,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": iso_utc(self.timestamp),
            "severity": self.severity.name,
            "type": self.alert_type,
            "score": self.score,
            "summary": self.summary,
            "network": self.network,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "channel": self.channel,
            "sensor": self.sensor,
            "stations": list(self.stations),
            "score_breakdown": [c.render() for c in self.components],
            "details": self.details,
            "suppressed_since_last": self.suppressed_count,
            "id": self.id,
        }


def unique(seq: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
