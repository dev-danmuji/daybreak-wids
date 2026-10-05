import errno
import io
import struct

import pytest

import frames_hex as F
from daybreak.dot11.frames import (
    LINKTYPE_IEEE802_11, LINKTYPE_RADIOTAP, FrameParseError, parse_frame, parse_radiotap,
)
from daybreak.dot11.rsn import RsnParseError, parse_rsn_ie, parse_rsnxe, parse_wpa1_ie
from daybreak.models import EventType
from daybreak.sensor.backend import BackendUnavailable
from daybreak.sensor.passive import PassiveBackend
from daybreak.sensor.pcapfile import CaptureFormatError, PcapFileBackend, iter_capture

TS = 1790000000.0
AP = "AA:BB:CC:DD:EE:FF"
STA = "10:22:33:44:55:66"


def rt(frame, header=F.RT_5180):
    return parse_frame(header + frame, linktype=LINKTYPE_RADIOTAP, timestamp=TS, sensor="alfa")


# -- radiotap ------------------------------------------------------------------------------

def test_radiotap_fields():
    info = parse_radiotap(F.RT_5180)
    assert info.length == 16 and info.freq == 5180 and info.rssi == -42 and not info.fcs_at_end
    ext = parse_radiotap(F.RT_EXT)
    assert ext.length == 32 and ext.freq == 5180 and ext.rssi == -64
    assert parse_radiotap(F.RT_2437_FCS).fcs_at_end


@pytest.mark.parametrize("buf", [b"", b"\x00\x00\x08", bytes.fromhex("01 00 08 00 00 00 00 00"),
                                 bytes.fromhex("00 00 40 00 00 00 00 00")])
def test_radiotap_malformed(buf):
    with pytest.raises(FrameParseError):
        parse_radiotap(buf)


def test_bad_fcs_frames_are_dropped():
    assert rt(F.DEAUTH_UNICAST, F.RT_BADFCS) is None


def test_fcs_is_stripped():
    ev = rt(F.DEAUTH_UNICAST + b"\xde\xad\xbe\xef", F.RT_2437_FCS)
    assert ev.reason_code == 7 and ev.channel == 6 and ev.rssi == -60


# -- deauth / disassoc ------------------------------------------------------------------------------

def test_unicast_deauth():
    ev = rt(F.DEAUTH_UNICAST)
    assert ev.event_type is EventType.DEAUTH
    assert (ev.bssid, ev.source, ev.destination, ev.station) == (AP, AP, STA, STA)
    assert ev.reason_code == 7 and ev.channel == 36 and ev.rssi == -42
    assert ev.protected is False and ev.metadata["frame_protection"] == "none"
    assert ev.metadata["seq"] == 100 and not ev.broadcast


def test_broadcast_disassoc():
    ev = rt(F.DISASSOC_BCAST)
    assert ev.event_type is EventType.DISASSOC and ev.broadcast and ev.station is None
    assert ev.reason_code == 3


def test_bip_protected_broadcast_deauth():
    ev = rt(F.DEAUTH_BCAST_BIP)
    assert ev.protected is True and ev.metadata["frame_protection"] == "bip"
    assert ev.reason_code == 7


def test_encrypted_unicast_deauth_has_no_reason():
    ev = rt(F.DEAUTH_PROTECTED)
    assert ev.protected is True and ev.reason_code is None
    assert ev.metadata["frame_protection"] == "encrypted"


def test_retry_flag():
    assert rt(F.DEAUTH_RETRY).metadata["retry"] is True
    assert "retry" not in rt(F.DEAUTH_UNICAST).metadata


# -- beacons / probe responses (WPA capability + PMF parser) -------------------------------------------

def test_beacon_transition_mode():
    ev = rt(F.BEACON_TRANSITION)
    assert ev.event_type is EventType.BEACON and ev.ssid == "ExampleSSID" and ev.channel == 36
    sec = ev.security
    assert sec.akms == ("PSK", "SAE") and sec.mode == "WPA2/WPA3-TRANSITION"
    assert sec.pmf == "capable" and sec.pairwise_ciphers == ("CCMP-128",)
    assert ev.metadata["phy"] == {"ht": True, "vht": False, "he": True, "eht": False}
    assert ev.metadata["beacon_interval"] == 100


def test_beacon_wpa3_pmf_required_h2e():
    sec = rt(F.BEACON_WPA3).security
    assert sec.mode == "WPA3-SAE" and sec.pmf == "required" and sec.sae_h2e is True


def test_probe_response_wpa2_no_pmf():
    ev = rt(F.PROBE_RESP_WPA2)
    assert ev.event_type is EventType.PROBE_RESP and ev.bssid == "02:13:37:00:00:01"
    assert ev.security.mode == "WPA2-PSK" and ev.security.pmf == "disabled" and ev.channel == 6


def test_hidden_open_beacon():
    ev = rt(F.BEACON_OPEN_HIDDEN)
    assert ev.ssid is None and ev.metadata["hidden"] and ev.security.mode == "OPEN"


def test_wpa1_vendor_element():
    sec = rt(F.BEACON_WPA1).security
    assert sec.wpa1 and not sec.rsn and sec.mode == "WPA" and sec.weak_ciphers == ("TKIP",)


def test_malformed_rsn_is_flagged_not_fatal():
    ev = rt(F.BEACON_BAD_RSN)
    assert ev.metadata["malformed"] == "rsn" and ev.security.rsn


def test_rsn_parser_details():
    info = parse_rsn_ie(bytes.fromhex("0100 000fac04 0100 000fac04 0100 000fac08 c000 0000 000fac06"))
    assert info.akms == ["SAE"] and info.mfp_required and info.mfp_capable
    assert info.group_mgmt_cipher == "BIP-CMAC-128" and info.pmkid_count == 0
    minimal = parse_rsn_ie(bytes.fromhex("0100"))  # all defaults
    assert minimal.pairwise == ["CCMP-128"] and minimal.akms == ["802.1X"]
    with pytest.raises(RsnParseError):
        parse_rsn_ie(bytes.fromhex("0200"))
    with pytest.raises(RsnParseError):
        parse_rsn_ie(bytes.fromhex("0100 000fac04 0100 000fac04 0100 000fac02 0000 0100"))  # PMKID missing
    assert parse_rsnxe(bytes.fromhex("20")) == {"protected_twt": False, "sae_h2e": True}
    wpa = parse_wpa1_ie(bytes.fromhex("0100 0050f202 0100 0050f202 0100 0050f202"))
    assert wpa.akms == ["PSK"] and wpa.pairwise == ["TKIP"]


# -- EAPOL metadata (Key Information only) ---------------------------------------------------------------

@pytest.mark.parametrize("frame,msg,src,dst", [
    (F.EAPOL_M1, 1, AP, STA), (F.EAPOL_M2, 2, STA, AP), (F.EAPOL_M3, 3, AP, STA), (F.EAPOL_M4, 4, STA, AP),
])
def test_eapol_message_numbers(frame, msg, src, dst):
    ev = rt(frame)
    assert ev.event_type is EventType.EAPOL and ev.bssid == AP and ev.station == STA
    assert (ev.source, ev.destination) == (src, dst)
    assert ev.metadata["eapol_type"] == "key" and ev.metadata["eapol_msg"] == msg
    allowed = {"seq", "eapol_type", "eapol_msg", "frequency", "retry"}
    assert set(ev.metadata) <= allowed  # nothing else is extracted from key frames


def test_eapol_start_and_ignored_data():
    assert rt(F.EAPOL_START).metadata["eapol_type"] == "start"
    assert rt(F.DATA_ENCRYPTED) is None
    assert rt(F.DATA_PLAIN_IP) is None


# -- auth / assoc / misc ------------------------------------------------------------------------------

def test_auth_and_assoc():
    a = rt(F.AUTH_OPEN)
    assert a.event_type is EventType.AUTH and a.station == STA and a.metadata["auth_alg"] == "open"
    assert rt(F.AUTH_SAE).metadata["auth_alg"] == "sae"
    req = rt(F.ASSOC_REQ)
    assert req.event_type is EventType.ASSOC and req.metadata["subtype"] == "req" and req.station == STA
    resp = rt(F.ASSOC_RESP)
    assert resp.metadata["subtype"] == "resp" and resp.metadata["status_code"] == 0


def test_irrelevant_frames_ignored():
    assert rt(F.PROBE_REQ) is None  # client probes are not recorded (privacy)
    assert rt(F.ACK) is None


def test_raw_80211_linktype_and_errors():
    ev = parse_frame(F.DEAUTH_UNICAST, linktype=LINKTYPE_IEEE802_11, timestamp=TS, default_channel=11)
    assert ev.channel == 11 and ev.rssi is None
    with pytest.raises(FrameParseError):
        parse_frame(b"\xc0\x00\x00", linktype=LINKTYPE_IEEE802_11, timestamp=TS)
    with pytest.raises(FrameParseError):
        parse_frame(F.DEAUTH_UNICAST, linktype=1, timestamp=TS)
    with pytest.raises(FrameParseError):
        parse_frame(F.BEACON_WPA3[:30], linktype=LINKTYPE_IEEE802_11, timestamp=TS)


def test_truncated_frames_never_crash():
    samples = [F.DEAUTH_UNICAST, F.BEACON_TRANSITION, F.EAPOL_M1, F.AUTH_OPEN, F.ASSOC_RESP]
    for sample in samples:
        frame = F.RT_5180 + sample
        for cut in range(len(frame)):
            try:
                parse_frame(frame[:cut], linktype=LINKTYPE_RADIOTAP, timestamp=TS)
            except FrameParseError:
                pass


# -- capture files ------------------------------------------------------------------------------------

def _pcap(frames, linktype=127):
    out = io.BytesIO()
    out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
    for i, frame in enumerate(frames):
        out.write(struct.pack("<IIII", int(TS) + i, 500000, len(frame), len(frame)))
        out.write(frame)
    return out.getvalue()


def _pcapng(frames, linktype=127):
    def block(btype, body):
        body += b"\x00" * ((4 - len(body) % 4) % 4)
        total = len(body) + 12
        return struct.pack("<II", btype, total) + body + struct.pack("<I", total)
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = block(1, struct.pack("<HHI", linktype, 0, 65535))
    out = shb + idb
    for i, frame in enumerate(frames):
        ts = int((TS + i) * 1e6)
        out += block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame)) + frame)
    return out


def test_pcap_and_pcapng_readers(tmp_path):
    frames = [F.RT_5180 + F.DEAUTH_UNICAST, F.RT_5180 + F.BEACON_WPA3, F.RT_5180 + F.PROBE_REQ,
              b"\x00\x00\x08"]
    for name, data in (("a.pcap", _pcap(frames)), ("b.pcapng", _pcapng(frames))):
        path = tmp_path / name
        path.write_bytes(data)
        records = list(iter_capture(io.BytesIO(data)))
        assert len(records) == 4 and records[0][1] == 127
        assert abs(records[1][0] - (TS + 1)) < 1.0
        backend = PcapFileBackend(path)
        backend.open()
        events = []
        while not backend.finished:
            events += backend.poll(0)
        backend.close()
        assert [e.event_type for e in events] == [EventType.DEAUTH, EventType.BEACON]
        assert backend.stats["unparsable"] == 1 and backend.stats["ignored"] == 1
    with pytest.raises(CaptureFormatError):
        list(iter_capture(io.BytesIO(b"not a capture file")))


# -- passive backend (fake socket; no AF_PACKET in tests) ----------------------------------------------

class FakeSock:
    def __init__(self, frames, error=None):
        self.frames = list(frames)
        self.error = error
        self.closed = False
        import os
        self._r, self._w = os.pipe()
        os.write(self._w, b"x")  # make select() report readable

    def fileno(self):
        return self._r

    def recv_into(self, buf):
        if self.frames:
            data = self.frames.pop(0)
            buf[:len(data)] = data
            return len(data)
        if self.error:
            raise OSError(self.error, "No such device")
        raise BlockingIOError

    def close(self):
        import os
        if not self.closed:
            os.close(self._r)
            os.close(self._w)
        self.closed = True


def _monitor_sysfs(tmp_path, iface="wlx00c0cab85c32", arphrd=803):
    d = tmp_path / iface
    d.mkdir(parents=True)
    (d / "type").write_text(f"{arphrd}\n")
    return tmp_path


def test_passive_backend_reads_metadata(tmp_path):
    sysfs = _monitor_sysfs(tmp_path)
    sock = FakeSock([F.RT_5180 + F.DEAUTH_UNICAST, F.RT_5180 + F.EAPOL_M1, b"\x00", F.RT_5180 + F.ACK])
    b = PassiveBackend("wlx00c0cab85c32", socket_factory=lambda i: sock, sysfs_root=sysfs)
    b.open()
    events = b.poll(0.1)
    assert [e.event_type for e in events] == [EventType.DEAUTH, EventType.EAPOL]
    assert b.stats == {"events": 2, "malformed": 0, "frames": 4, "unparsable": 1, "ignored": 1}
    assert not hasattr(sock, "send") and not hasattr(b, "send")
    b.close()


def test_passive_backend_requires_monitor_mode(tmp_path):
    sysfs = _monitor_sysfs(tmp_path, arphrd=1)  # ARPHRD_ETHER: managed mode
    b = PassiveBackend("wlx00c0cab85c32", socket_factory=lambda i: FakeSock([]), sysfs_root=sysfs)
    with pytest.raises(BackendUnavailable, match="not in monitor mode"):
        b.open()


def test_passive_backend_sensor_disappears(tmp_path):
    sysfs = _monitor_sysfs(tmp_path)
    b = PassiveBackend("wlx00c0cab85c32", socket_factory=lambda i: FakeSock([], error=errno.ENODEV),
                       sysfs_root=sysfs)
    b.open()
    with pytest.raises(BackendUnavailable, match="went away"):
        b.poll(0.1)
    assert not b.status().healthy
    with pytest.raises(BackendUnavailable):
        b.poll(0.1)


def test_passive_backend_channel_hopping(tmp_path):
    sysfs = _monitor_sysfs(tmp_path)
    now = [100.0]
    tuned = []
    b = PassiveBackend("wlx00c0cab85c32", socket_factory=lambda i: FakeSock([]), sysfs_root=sysfs,
                       channels=[36, 6, 36], dwell=0.5, set_channel=tuned.append, clock=lambda: now[0])
    b.open()
    for _ in range(3):
        now[0] += 0.6
        b.poll(0)
    assert tuned == [36, 6, 36, 6]
