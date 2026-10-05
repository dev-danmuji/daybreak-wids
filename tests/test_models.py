import math

import pytest

from daybreak.models import (
    Alert, Event, EventType, MalformedEventError, ScoreComponent, SecurityProfile, Severity,
    is_group_address, normalize_mac, parse_timestamp, sanitize_metadata, try_normalize_mac,
)


class TestBssidNormalization:
    @pytest.mark.parametrize("raw", [
        "aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff",
        "AABBCCDDEEFF", " aa:bb:cc:dd:ee:ff ", bytes.fromhex("aabbccddeeff"),
    ])
    def test_formats(self, raw):
        assert normalize_mac(raw) == "AA:BB:CC:DD:EE:FF"

    def test_short_octets_are_padded(self):
        assert normalize_mac("0:1:2:a:b:c") == "00:01:02:0A:0B:0C"

    @pytest.mark.parametrize("raw", ["", "aa:bb:cc:dd:ee", "gg:bb:cc:dd:ee:ff", "aabbccddeeff00",
                                     "aa:bb:cc:dd:ee:ff:00", 12345, None, b"\x00\x01"])
    def test_invalid(self, raw):
        with pytest.raises(ValueError):
            normalize_mac(raw)
        assert try_normalize_mac(raw) is None

    def test_group_address(self):
        assert is_group_address("FF:FF:FF:FF:FF:FF")
        assert is_group_address("01:00:5E:00:00:01")
        assert not is_group_address("AA:BB:CC:DD:EE:FF")
        assert not is_group_address(None)


class TestTimestamps:
    def test_epoch_and_iso(self):
        assert parse_timestamp(1790000000) == 1790000000.0
        assert parse_timestamp("1790000000.5") == 1790000000.5
        assert parse_timestamp("2026-10-05T06:31:11Z") == parse_timestamp("2026-10-05T15:31:11+09:00")

    @pytest.mark.parametrize("raw", ["yesterday", -5, 0, math.nan, math.inf, True, None, [1]])
    def test_invalid(self, raw):
        with pytest.raises(ValueError):
            parse_timestamp(raw)


class TestSeverity:
    @pytest.mark.parametrize("score,expected", [
        (0, Severity.INFO), (29, Severity.INFO), (30, Severity.LOW), (49, Severity.LOW),
        (50, Severity.MEDIUM), (69, Severity.MEDIUM), (70, Severity.HIGH), (89, Severity.HIGH),
        (90, Severity.CRITICAL), (100, Severity.CRITICAL),
    ])
    def test_bands(self, score, expected):
        assert Severity.from_score(score) is expected

    def test_parse(self):
        assert Severity.parse("high") is Severity.HIGH
        with pytest.raises(ValueError):
            Severity.parse("urgent")


class TestEventParsing:
    def test_deauth_event(self):
        e = Event.from_dict({
            "ts": "2026-10-05T06:31:11Z", "type": "deauth", "bssid": "aa:bb:cc:dd:ee:ff",
            "src": "aa:bb:cc:dd:ee:ff", "dst": "10:22:33:44:55:66", "reason": 7,
            "channel": 36, "rssi": -40, "protected": False, "seq": 12,
        })
        assert e.event_type is EventType.DEAUTH
        assert e.station == "10:22:33:44:55:66"
        assert e.reason_code == 7 and not e.broadcast
        assert e.metadata == {"seq": 12}

    def test_broadcast_has_no_station(self):
        e = Event.from_dict({"ts": 1790000000, "type": "disassoc", "bssid": "aa:bb:cc:dd:ee:ff",
                             "src": "aa:bb:cc:dd:ee:ff", "dst": "ff:ff:ff:ff:ff:ff"})
        assert e.broadcast and e.station is None

    def test_client_to_ap(self):
        e = Event.from_dict({"ts": 1790000000, "type": "eapol", "bssid": "aa:bb:cc:dd:ee:ff",
                             "src": "10:22:33:44:55:66", "dst": "aa:bb:cc:dd:ee:ff", "eapol_msg": 2})
        assert e.station == "10:22:33:44:55:66"
        assert e.metadata["eapol_msg"] == 2

    @pytest.mark.parametrize("data,msg", [
        ({"type": "deauth"}, "missing timestamp"),
        ({"ts": 1790000000}, "missing event type"),
        ({"ts": 1790000000, "type": "teleport"}, "unknown event type"),
        ({"ts": 1790000000, "type": "deauth", "bssid": "not-a-mac"}, "invalid MAC"),
        ({"ts": 1790000000, "type": "deauth", "channel": 999}, "channel out of range"),
        ({"ts": 1790000000, "type": "deauth", "channel": "abc"}, "invalid literal"),
        ({"ts": 1790000000, "type": "deauth", "protected": "yes"}, "protected must be"),
        ({"ts": 1790000000, "type": "beacon", "ssid": "x" * 33}, "longer than 32"),
        ({"ts": 1790000000, "type": "beacon", "security": "WPA3"}, "security must be"),
        ({"ts": 1790000000, "type": "deauth", "metadata": [1]}, "metadata must be"),
        ({"ts": "garbage", "type": "deauth"}, "invalid timestamp"),
    ])
    def test_malformed(self, data, msg):
        with pytest.raises(MalformedEventError, match=msg):
            Event.from_dict(data)

    def test_malformed_json(self):
        with pytest.raises(MalformedEventError):
            Event.from_json("{not json")
        with pytest.raises(MalformedEventError):
            Event.from_json("[1, 2]")

    def test_out_of_range_rssi_is_dropped_not_fatal(self):
        e = Event.from_dict({"ts": 1790000000, "type": "deauth", "rssi": -300})
        assert e.rssi is None

    def test_roundtrip(self):
        e = Event.from_dict({"ts": 1790000000.25, "type": "beacon", "bssid": "aa:bb:cc:dd:ee:ff",
                             "ssid": "ExampleSSID", "channel": 36,
                             "security": {"akms": ["SAE"], "pmf": "required"}})
        again = Event.from_dict(e.to_dict())
        assert again.security.mode == "WPA3-SAE"
        assert again.fingerprint() == e.fingerprint()


class TestSanitization:
    def test_sensitive_keys_are_removed(self):
        md = sanitize_metadata({
            "eapol_msg": 1, "nonce": "00" * 32, "mic": "ab" * 16, "pmkid": "cd" * 16,
            "key_data": "...", "replay_counter": 5, "passphrase": "hunter2", "raw": b"\x00",
            "seq": 3, "unknown_field": "dropped",
        })
        assert md == {"eapol_msg": 1, "seq": 3}

    def test_event_from_dict_strips_key_material(self):
        e = Event.from_dict({"ts": 1790000000, "type": "eapol", "bssid": "aa:bb:cc:dd:ee:ff",
                             "station": "10:22:33:44:55:66", "anonce": "11" * 32,
                             "metadata": {"snonce": "22" * 32, "eapol_msg": 2}})
        assert e.metadata == {"eapol_msg": 2}
        assert "11" * 32 not in str(e.to_dict())

    def test_long_text_truncated(self):
        assert len(sanitize_metadata({"note": "x" * 5000})["note"]) == 512


class TestSecurityProfile:
    def test_modes(self):
        assert SecurityProfile().mode == "OPEN"
        assert SecurityProfile(privacy=True).mode == "WEP"
        wpa2 = SecurityProfile(privacy=True, rsn=True, akms=("PSK",), mfp_capable=False)
        assert wpa2.mode == "WPA2-PSK" and wpa2.pmf == "disabled"
        trans = SecurityProfile(privacy=True, rsn=True, akms=("PSK", "SAE"), mfp_capable=True)
        assert trans.mode == "WPA2/WPA3-TRANSITION" and trans.transition_mode and trans.pmf == "capable"
        wpa3 = SecurityProfile(privacy=True, rsn=True, akms=("SAE",), mfp_capable=True, mfp_required=True)
        assert wpa3.mode == "WPA3-SAE" and wpa3.pmf == "required"
        assert wpa3.rank > trans.rank > wpa2.rank > SecurityProfile(privacy=True).rank

    def test_from_dict_pmf_shortcut(self):
        p = SecurityProfile.from_dict({"akms": ["sae"], "pmf": "required"})
        assert p.mfp_required and p.mfp_capable and p.rsn and p.privacy
        with pytest.raises(ValueError):
            SecurityProfile.from_dict({"pmf": "sometimes"})


def test_alert_score_clamped_and_rendered():
    a = Alert("X", 1790000000, 150, [ScoreComponent(30, "deauth burst", "37 frames/5s")])
    assert a.score == 100 and a.severity is Severity.CRITICAL
    assert a.score_lines() == ["+30 deauth burst (37 frames/5s)"]
    assert a.to_dict()["severity"] == "CRITICAL"
