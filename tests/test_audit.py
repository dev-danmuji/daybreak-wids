import frames_hex as F
from conftest import HOME_BSSID, HOME_BSSID_24G, ROGUE_BSSID, make_config
from daybreak.config import ProtectedNetwork, SecurityExpectation
from daybreak.detectors.security import (
    INFO, OK, RISK, WARN, APObservation, assess_profile, audit_network, observations_from_rows,
    render_audit,
)
from daybreak.dot11.frames import LINKTYPE_RADIOTAP, parse_frame
from daybreak.models import SecurityProfile
from daybreak.policy import policy_checklist, render_checklist
from daybreak.storage import Database
from test_correlation import run_fixture


def prof(**kw):
    return SecurityProfile.from_dict(kw)


def levels(items):
    return {i.title: i.level for i in items}


def test_transition_mode_audit_matches_spec_example():
    net = ProtectedNetwork(name="home", ssid="ExampleSSID", bssids=[HOME_BSSID])
    audit = audit_network(net, [APObservation(HOME_BSSID, prof(akms=["PSK", "SAE"], pmf="capable"), 36)])
    text = render_audit(audit)
    assert "SSID: ExampleSSID" in text
    assert "WPA2/WPA3 Transition : enabled" in text
    assert "PMF                  : capable" in text
    assert "PMF required         : no" in text
    assert "Consider WPA3-SAE + PMF required if every client supports it." in text
    assert "never changes AP settings" in text


def test_profiles():
    items, recs = assess_profile(prof(akms=["SAE"], pmf="required", sae_h2e=True))
    assert levels(items) == {"WPA3-SAE": OK, "PMF required": OK} and recs == []
    items, recs = assess_profile(prof(akms=["PSK"], pmf="disabled"))
    assert levels(items)["WPA2-PSK only"] == WARN and levels(items)["PMF disabled"] == WARN
    assert any("WPA3-SAE" in r for r in recs) and any("802.11w" in r for r in recs)
    items, _ = assess_profile(SecurityProfile())
    assert levels(items) == {"no encryption": RISK}
    items, _ = assess_profile(SecurityProfile(privacy=True))
    assert levels(items) == {"WEP": RISK}
    items, recs = assess_profile(prof(wpa1=True, rsn=False, akms=["PSK"], pairwise_ciphers=["TKIP"]))
    assert levels(items)["weak cipher"] == RISK
    items, _ = assess_profile(prof(akms=["SAE"], pmf="capable"))
    assert levels(items)["WPA3 without PMF required"] == WARN
    items, recs = assess_profile(prof(akms=["SAE"], pmf="required", sae_h2e=False, wps=True))
    assert levels(items)["WPS advertised"] == WARN and "Disable WPS on the router." in recs
    assert levels(items)["SAE hash-to-element not advertised"] == INFO


def test_wps_detected_from_beacon_elements():
    beacon = F.BEACON_WPA3[:] + bytes.fromhex("dd 05 00 50 f2 04 10")
    ev = parse_frame(F.RT_5180 + beacon, linktype=LINKTYPE_RADIOTAP, timestamp=1.79e9)
    assert ev.security.wps is True
    items, _ = assess_profile(ev.security)
    assert "WPS advertised" in levels(items)


def test_inconsistent_radios_and_unknown_bssids():
    net = ProtectedNetwork(name="home", ssid="ExampleSSID", bssids=[HOME_BSSID, HOME_BSSID_24G],
                           security=SecurityExpectation(expected=["WPA3"]))
    audit = audit_network(net, [
        APObservation(HOME_BSSID, prof(akms=["SAE"], pmf="required")),
        APObservation(HOME_BSSID_24G, prof(akms=["PSK"], pmf="disabled")),
        APObservation(ROGUE_BSSID, prof(akms=["PSK"], pmf="disabled")),
    ])
    lv = levels(audit.items)
    assert lv["inconsistent security across BSSIDs"] == WARN
    assert lv["differs from registry expectation"] == WARN
    assert lv["unregistered BSSIDs advertise this SSID"] == WARN
    assert audit.profile.mode == "WPA2-PSK"  # the weakest registered radio is what matters
    assert audit.items[0].level in (RISK, WARN)
    assert audit.to_dict()["unknown_bssids"] == [ROGUE_BSSID]


def test_unconfigured_network_lists_candidates_only():
    net = ProtectedNetwork(name="lab", ssid="LabNet")
    audit = audit_network(net, [APObservation(ROGUE_BSSID, prof(akms=["PSK"]))])
    assert audit.aps == [] and [a.bssid for a in audit.unknown] == [ROGUE_BSSID]
    assert "Candidates (unregistered)" in render_audit(audit)


def test_audit_from_database_rows(tmp_path):
    cfg = make_config(tmp_path)
    db = Database(cfg.database_path)
    p, _ = run_fixture(cfg, "evil_twin.jsonl", db=db)
    p.flush()
    rows = db.list_aps(ssid="ExampleSSID")
    obs = observations_from_rows(rows)
    assert {o.bssid for o in obs} == {HOME_BSSID, ROGUE_BSSID}
    audit = audit_network(cfg.network("home"), obs)
    assert [a.bssid for a in audit.aps] == [HOME_BSSID]
    assert audit.profile.mode == "WPA2/WPA3-TRANSITION"
    assert [a.bssid for a in audit.unknown] == [ROGUE_BSSID]


def test_password_policy_checklist_never_takes_a_psk():
    items = policy_checklist(prof(akms=["PSK", "SAE"], pmf="capable", wps=None))
    keys = [i.key for i in items]
    assert keys == ["wpa3", "pmf", "passphrase", "default-psk", "admin", "wps", "guest"]
    by = {i.key: i for i in items}
    assert by["wpa3"].status == "attention" and by["pmf"].status == "attention"
    assert by["wps"].status == "ok"  # parsed beacons contained no WPS element
    text = render_checklist(items, "ExampleSSID")
    assert "never asks for or stores your Wi-Fi passphrase" in text
    assert "20 random characters" in text and "Disable WPS" in text
    ok = {i.key: i.status for i in policy_checklist(prof(akms=["SAE"], pmf="required"))}
    assert ok["wpa3"] == "ok" and ok["pmf"] == "ok"
    assert all(i.status == "check" for i in policy_checklist(None))


def test_unregistered_bssids_are_flagged_even_if_the_ap_is_not_heard():
    net = make_config_network()
    obs = [APObservation(bssid=f"02:00:00:00:00:{i:02X}", profile=None, channel=36, last_seen=float(i))
           for i in range(25)]
    audit = audit_network(net, obs)
    titles = [i.title for i in audit.items]
    assert "unregistered BSSIDs advertise this SSID" in titles and "not observed" in titles
    detail = next(i.detail for i in audit.items if i.title.startswith("unregistered"))
    assert detail.endswith("(+5 more)") and detail.count(":") == 20 * 5
    text = render_audit(audit)
    assert "02:00:00:00:00:18" in text and "02:00:00:00:00:04" not in text  # most recent 20 listed
    assert "... and 5 more (most recently seen shown)" in text


def make_config_network():
    return ProtectedNetwork(name="home", ssid="ExampleSSID", bssids=[HOME_BSSID, HOME_BSSID_24G],
                            security=SecurityExpectation(expected=["WPA2", "WPA3"], pmf="capable"))
