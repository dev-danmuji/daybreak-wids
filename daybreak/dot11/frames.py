"""Radiotap + IEEE 802.11 *metadata* extraction for received frames.

The parser turns a captured frame into an :class:`~daybreak.models.Event`
holding addresses, subtype, reason code, channel, RSSI and capability flags.
It deliberately does not look at frame payloads beyond what detection needs:
for EAPOL-Key frames only the 2-byte Key Information field is read, so
nonces, MICs, replay counters and key data are never extracted.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ..models import Event, EventType, normalize_mac
from . import ieee80211 as d
from .ieee80211 import freq_to_channel
from .rsn import security_from_elements

LINKTYPE_IEEE802_11 = 105
LINKTYPE_PPI = 192
LINKTYPE_RADIOTAP = 127

# radiotap field bit -> (alignment, size), in presence order
_RT_FIELDS = {
    0: (8, 8),   # TSFT
    1: (1, 1),   # Flags
    2: (1, 1),   # Rate
    3: (2, 4),   # Channel (freq u16, flags u16)
    4: (2, 2),   # FHSS
    5: (1, 1),   # dBm antenna signal
}
RT_FLAG_FCS = 0x10
RT_FLAG_BADFCS = 0x40


class FrameParseError(ValueError):
    pass


@dataclass
class RadiotapInfo:
    length: int
    flags: int | None = None
    freq: int | None = None
    rssi: int | None = None

    @property
    def fcs_at_end(self) -> bool:
        return bool(self.flags and self.flags & RT_FLAG_FCS)

    @property
    def bad_fcs(self) -> bool:
        return bool(self.flags and self.flags & RT_FLAG_BADFCS)


def parse_radiotap(buf: bytes) -> RadiotapInfo:
    if len(buf) < 8:
        raise FrameParseError("radiotap header too short")
    version, _pad, length, present = struct.unpack_from("<BBHI", buf, 0)
    if version != 0:
        raise FrameParseError(f"unsupported radiotap version {version}")
    if length < 8 or length > len(buf):
        raise FrameParseError("invalid radiotap length")
    info = RadiotapInfo(length=length)
    off = 8
    word = present
    while word & 0x80000000:  # extended presence bitmaps
        if off + 4 > length:
            raise FrameParseError("truncated radiotap presence bitmap")
        (word,) = struct.unpack_from("<I", buf, off)
        off += 4
    for bit in range(0, 6):
        if not present & (1 << bit):
            continue
        align, size = _RT_FIELDS[bit]
        off = (off + align - 1) & ~(align - 1)
        if off + size > length:
            raise FrameParseError("truncated radiotap field")
        if bit == 1:
            info.flags = buf[off]
        elif bit == 3:
            info.freq = struct.unpack_from("<H", buf, off)[0] or None
        elif bit == 5:
            info.rssi = struct.unpack_from("<b", buf, off)[0]
        off += size
    return info


def iter_elements(data: bytes) -> tuple[dict[int, list[bytes]], bool]:
    """Split tagged elements; returns ({id: [payload, ...]}, truncated)."""
    out: dict[int, list[bytes]] = {}
    off = 0
    while off + 2 <= len(data):
        eid, elen = data[off], data[off + 1]
        if off + 2 + elen > len(data):
            return out, True
        out.setdefault(eid, []).append(data[off + 2: off + 2 + elen])
        off += 2 + elen
    return out, off != len(data)


def _mac(raw: bytes) -> str:
    return normalize_mac(raw)


def _eapol_message(key_info: int) -> int | None:
    if not key_info & d.KI_PAIRWISE:
        return None
    ack, mic = key_info & d.KI_ACK, key_info & d.KI_MIC
    if ack and not mic:
        return 1
    if ack and mic:
        return 3
    if mic and not ack:
        return 4 if key_info & d.KI_SECURE else 2
    return None


def parse_frame(buf: bytes, *, linktype: int, timestamp: float, sensor: str = "",
                default_channel: int | None = None) -> Event | None:
    """Return an Event for frames relevant to detection, else ``None``.

    Raises :class:`FrameParseError` for frames that are too malformed to read.
    """
    rssi = None
    freq = None
    if linktype == LINKTYPE_RADIOTAP:
        rt = parse_radiotap(buf)
        if rt.bad_fcs:
            return None
        frame = buf[rt.length:]
        if rt.fcs_at_end:
            frame = frame[:-4]
        rssi, freq = rt.rssi, rt.freq
    elif linktype == LINKTYPE_PPI:
        if len(buf) < 8:
            raise FrameParseError("PPI header too short")
        (plen,) = struct.unpack_from("<H", buf, 2)
        (dlt,) = struct.unpack_from("<I", buf, 4)
        if dlt != LINKTYPE_IEEE802_11 or plen > len(buf):
            raise FrameParseError("unsupported PPI payload")
        frame = buf[plen:]
    elif linktype == LINKTYPE_IEEE802_11:
        frame = buf
    else:
        raise FrameParseError(f"unsupported link type {linktype}")

    if len(frame) < 10:
        raise FrameParseError("802.11 header too short")
    fc0, flags = frame[0], frame[1]
    ftype = (fc0 >> 2) & 0x3
    subtype = (fc0 >> 4) & 0xF
    if (fc0 & 0x3) != 0:
        raise FrameParseError("unsupported 802.11 protocol version")
    channel = freq_to_channel(freq)[0] if freq else default_channel
    if rssi is not None and not -127 <= rssi < 0:
        rssi = None

    if ftype == d.TYPE_MGMT:
        return _parse_mgmt(frame, subtype, flags, timestamp, sensor, channel, rssi, freq)
    if ftype == d.TYPE_DATA:
        return _parse_data(frame, subtype, flags, timestamp, sensor, channel, rssi, freq)
    return None


def _base_md(frame: bytes, flags: int, freq: int | None) -> dict:
    md: dict = {}
    if len(frame) >= 24:
        (seqctl,) = struct.unpack_from("<H", frame, 22)
        md["seq"] = seqctl >> 4
    if flags & d.FC_RETRY:
        md["retry"] = True
    if freq:
        md["frequency"] = freq
    return md


def _parse_mgmt(frame: bytes, subtype: int, flags: int, ts: float, sensor: str,
                channel: int | None, rssi: int | None, freq: int | None) -> Event | None:
    if len(frame) < 24:
        raise FrameParseError("management header too short")
    addr1, addr2, addr3 = _mac(frame[4:10]), _mac(frame[10:16]), _mac(frame[16:22])
    body = frame[24:]
    md = _base_md(frame, flags, freq)
    protected = bool(flags & d.FC_PROTECTED)

    if subtype in (d.MGMT_DEAUTH, d.MGMT_DISASSOC):
        etype = EventType.DEAUTH if subtype == d.MGMT_DEAUTH else EventType.DISASSOC
        reason = None
        group = bool(frame[4] & 0x01)
        if protected:
            md["frame_protection"] = "encrypted"  # unicast robust frame (CCMP/GCMP)
        elif len(body) >= 2:
            (reason,) = struct.unpack_from("<H", body, 0)
            if group:
                elements, _ = iter_elements(body[2:])
                if d.EID_MMIE in elements:
                    protected = True
                    md["frame_protection"] = "bip"
        else:
            md["malformed"] = "short body"
        md.setdefault("frame_protection", "bip" if protected else "none")
        ev = Event(ts, etype, sensor=sensor, bssid=addr3, source=addr2, destination=addr1,
                   channel=channel, rssi=rssi, reason_code=reason, protected=protected, metadata=md)
        ev.derive_station()
        return ev

    if subtype in (d.MGMT_BEACON, d.MGMT_PROBE_RESP):
        if len(body) < 12:
            raise FrameParseError("beacon body too short")
        interval, cap = struct.unpack_from("<HH", body, 8)
        elements, truncated = iter_elements(body[12:])
        ssid_raw = (elements.get(d.EID_SSID) or [b""])[0]
        hidden = not ssid_raw or not ssid_raw.strip(b"\x00")
        ssid = None if hidden else ssid_raw[:32].decode("utf-8", "replace")
        ds = elements.get(d.EID_DS_PARAMS)
        if ds and ds[0]:
            ie_channel = ds[0][0]
            if 1 <= ie_channel <= 233 and (freq is None or freq_to_channel(freq)[1] != "6"):
                channel = ie_channel
        profile, malformed = security_from_elements(bool(cap & d.CAP_PRIVACY), elements)
        ext = [p[0] for p in elements.get(d.EID_EXTENSION, []) if p]
        md.update({
            "beacon_interval": interval,
            "phy": {"ht": d.EID_HT_CAP in elements, "vht": d.EID_VHT_CAP in elements,
                    "he": d.EXT_HE_CAP in ext, "eht": d.EXT_EHT_CAP in ext},
        })
        if hidden:
            md["hidden"] = True
        if truncated or malformed:
            md["malformed"] = ",".join(malformed + (["elements"] if truncated else []))
        etype = EventType.BEACON if subtype == d.MGMT_BEACON else EventType.PROBE_RESP
        return Event(ts, etype, sensor=sensor, bssid=addr3, source=addr2, destination=addr1,
                     channel=channel, rssi=rssi, ssid=ssid, security=profile, metadata=md)

    if subtype == d.MGMT_AUTH:
        if len(body) < 6:
            raise FrameParseError("authentication body too short")
        alg, seq, status = struct.unpack_from("<HHH", body, 0)
        md.update({"auth_alg": d.AUTH_ALGORITHMS.get(alg, str(alg)), "auth_seq": seq, "status_code": status})
        ev = Event(ts, EventType.AUTH, sensor=sensor, bssid=addr3, source=addr2, destination=addr1,
                   channel=channel, rssi=rssi, metadata=md)
        ev.derive_station()
        return ev

    if subtype in (d.MGMT_ASSOC_REQ, d.MGMT_ASSOC_RESP, d.MGMT_REASSOC_REQ, d.MGMT_REASSOC_RESP):
        etype = EventType.ASSOC if subtype in (d.MGMT_ASSOC_REQ, d.MGMT_ASSOC_RESP) else EventType.REASSOC
        md["subtype"] = "resp" if subtype in (d.MGMT_ASSOC_RESP, d.MGMT_REASSOC_RESP) else "req"
        if md["subtype"] == "resp" and len(body) >= 4:
            md["status_code"] = struct.unpack_from("<H", body, 2)[0]
        ev = Event(ts, etype, sensor=sensor, bssid=addr3, source=addr2, destination=addr1,
                   channel=channel, rssi=rssi, metadata=md)
        ev.derive_station()
        return ev
    return None


def _parse_data(frame: bytes, subtype: int, flags: int, ts: float, sensor: str,
                channel: int | None, rssi: int | None, freq: int | None) -> Event | None:
    if subtype & 0x4:  # null / QoS-null: no payload
        return None
    if flags & d.FC_PROTECTED:
        return None  # encrypted payload: nothing to inspect
    to_ds, from_ds = bool(flags & d.FC_TODS), bool(flags & d.FC_FROMDS)
    if to_ds and from_ds:
        return None  # WDS / mesh: out of scope
    hdr = 24 + (2 if subtype & 0x8 else 0)
    if subtype & 0x8 and flags & d.FC_ORDER:
        hdr += 4
    if len(frame) < hdr + 8 or frame[hdr:hdr + 8] != d.LLC_SNAP_EAPOL:
        return None
    addr1, addr2, addr3 = _mac(frame[4:10]), _mac(frame[10:16]), _mac(frame[16:22])
    if to_ds:
        bssid, src, dst = addr1, addr2, addr3
    elif from_ds:
        bssid, src, dst = addr2, addr3, addr1
    else:
        bssid, src, dst = addr3, addr2, addr1
    eapol = frame[hdr + 8:]
    if len(eapol) < 4:
        raise FrameParseError("EAPOL header too short")
    etype_code = eapol[1]
    md = _base_md(frame, flags, freq)
    if etype_code == d.EAPOL_TYPE_KEY:
        md["eapol_type"] = "key"
        if len(eapol) >= 7:
            (key_info,) = struct.unpack_from(">H", eapol, 5)
            msg = _eapol_message(key_info)
            if msg is not None:
                md["eapol_msg"] = msg
            else:
                md["eapol_type"] = "group_key" if not key_info & d.KI_PAIRWISE else "key"
    elif etype_code == d.EAPOL_TYPE_EAP:
        md["eapol_type"] = "eap"
        if len(eapol) >= 5:
            md["eap_code"] = eapol[4]
    elif etype_code == d.EAPOL_TYPE_START:
        md["eapol_type"] = "start"
    elif etype_code == d.EAPOL_TYPE_LOGOFF:
        md["eapol_type"] = "logoff"
    else:
        md["eapol_type"] = f"type-{etype_code}"
    ev = Event(ts, EventType.EAPOL, sensor=sensor, bssid=bssid, source=src, destination=dst,
               channel=channel, rssi=rssi, metadata=md)
    ev.derive_station()
    return ev
