#!/usr/bin/env python3
"""Generate the synthetic metadata fixtures in this directory (deterministic).

    python tests/fixtures/make_fixtures.py

Every line is a *metadata* event (addresses, timing, reason codes, EAPOL
message numbers). No frame payloads, nonces, MICs, PMKIDs or other key
material exist in these files. Addresses use locally administered or
documentation-style values.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).parent
T0 = datetime(2026, 10, 5, 6, 0, 0, tzinfo=timezone.utc)  # 15:00 KST

AP = "AA:BB:CC:DD:EE:FF"          # registered BSSID of "home" (5 GHz, ch 36)
AP2 = "AA:BB:CC:DD:EE:F0"         # registered second radio (2.4 GHz, ch 6)
ROGUE = "02:13:37:00:00:01"       # not registered
STAS = ["10:22:33:44:55:01", "10:22:33:44:55:02", "10:22:33:44:55:03", "10:22:33:44:55:04"]
BCAST = "FF:FF:FF:FF:FF:FF"
SSID = "ExampleSSID"

TRANSITION = {"akms": ["PSK", "SAE"], "pairwise_ciphers": ["CCMP-128"], "group_cipher": "CCMP-128",
              "pmf": "capable"}
WPA2_ONLY = {"akms": ["PSK"], "pairwise_ciphers": ["CCMP-128"], "group_cipher": "CCMP-128",
             "pmf": "disabled"}


def ts(seconds: float) -> str:
    t = T0 + timedelta(seconds=seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


class Stream:
    def __init__(self):
        self.lines: list[tuple[float, dict]] = []
        self.seq: dict[str, int] = {}

    def _seq(self, src: str) -> int:
        self.seq[src] = (self.seq.get(src, 0) + 1) % 4096
        return self.seq[src]

    def add(self, t: float, **ev) -> None:
        ev = {"ts": ts(t), **ev}
        if "src" in ev and ev.get("type") not in ("beacon", "kismet_alert", "sensor"):
            ev["seq"] = self._seq(ev["src"])
        self.lines.append((t, ev))

    def beacons(self, start: float, end: float, bssid=AP, channel=36, rssi=-41, security=None,
                every: float = 10.0, rng=None):
        t = start
        while t < end:
            jitter = rng.randint(-2, 2) if rng else 0
            self.add(t, type="beacon", bssid=bssid, src=bssid, ssid=SSID, channel=channel,
                     rssi=rssi + jitter, security=security or TRANSITION)
            t += every

    def connect(self, t: float, sta: str, bssid=AP, channel=36, rssi=-55, reassoc=False):
        """Authentication, (re)association and a complete 4-way handshake (message numbers only)."""
        self.add(t, type="auth", bssid=bssid, src=sta, dst=bssid, channel=channel, rssi=rssi, auth_alg="sae")
        self.add(t + 0.01, type="auth", bssid=bssid, src=bssid, dst=sta, channel=channel, rssi=-41,
                 auth_alg="sae")
        kind = "reassoc" if reassoc else "assoc"
        self.add(t + 0.02, type=kind, bssid=bssid, src=sta, dst=bssid, channel=channel, rssi=rssi, subtype="req")
        self.add(t + 0.03, type=kind, bssid=bssid, src=bssid, dst=sta, channel=channel, rssi=-41,
                 subtype="resp", status_code=0)
        for i, msg in enumerate((1, 2, 3, 4)):
            src, dst = (bssid, sta) if msg in (1, 3) else (sta, bssid)
            self.add(t + 0.05 + i * 0.01, type="eapol", bssid=bssid, src=src, dst=dst, channel=channel,
                     rssi=-41 if src == bssid else rssi, eapol_type="key", eapol_msg=msg)

    def write(self, name: str, header: str) -> None:
        self.lines.sort(key=lambda item: item[0])
        path = HERE / name
        with open(path, "w", encoding="utf-8") as fh:
            for line in header.strip().splitlines():
                fh.write(f"# {line}\n")
            for _t, ev in self.lines:
                fh.write(json.dumps(ev, separators=(",", ":")) + "\n")
        print(f"wrote {path} ({len(self.lines)} events)")


def normal():
    rng = random.Random(1)
    s = Stream()
    s.beacons(0, 900, rng=rng)
    s.beacons(3, 900, bssid=AP2, channel=6, rssi=-48, rng=rng)
    for i, sta in enumerate(STAS):
        s.connect(5 + i * 7, sta)
    # station 1 roams to the 2.4 GHz radio and back (client-initiated, reason 8)
    s.add(200, type="disassoc", bssid=AP, src=STAS[0], dst=AP, channel=36, rssi=-60, reason=8)
    s.connect(201, STAS[0], bssid=AP2, channel=6, reassoc=True)
    s.add(420, type="disassoc", bssid=AP2, src=STAS[0], dst=AP2, channel=6, rssi=-58, reason=8)
    s.connect(421, STAS[0], reassoc=True)
    # AP removes an idle station (reason 4), a station leaves (reason 3) and comes back later
    s.add(300, type="disassoc", bssid=AP, src=AP, dst=STAS[3], channel=36, rssi=-41, reason=4)
    s.add(610, type="deauth", bssid=AP, src=STAS[2], dst=AP, channel=36, rssi=-57, reason=3)
    s.connect(700, STAS[2])
    s.connect(720, STAS[3])
    # periodic group key update: two group-key EAPOL frames per station
    for i, sta in enumerate(STAS):
        s.add(600 + i, type="eapol", bssid=AP, src=AP, dst=sta, channel=36, rssi=-41, eapol_type="group_key")
        s.add(600.02 + i, type="eapol", bssid=AP, src=sta, dst=AP, channel=36, rssi=-55, eapol_type="group_key")
    # an AP restart: a single broadcast deauth (normal, must not alert as an attack)
    s.add(800, type="deauth", bssid=AP, src=AP, dst=BCAST, channel=36, rssi=-41, reason=3)
    for i, sta in enumerate(STAS):
        s.connect(830 + i * 3, sta)
    s.write("normal.jsonl", """
Normal day: beacons, initial connections, roaming between the two registered
radios, idle disconnects, group rekeys, one AP restart. Expected: no HIGH alert.
""")


def deauth_burst():
    rng = random.Random(2)
    s = Stream()
    s.beacons(0, 180, rng=rng, every=5.0)
    for i, sta in enumerate(STAS):
        s.connect(2 + i * 3, sta)
    # 37 spoofed disconnect frames within 5 s claiming the AP, weaker signal than the real AP
    for i in range(37):
        t = 60 + i * (4.8 / 37)
        dst = BCAST if i % 5 == 0 else STAS[i % 4]
        kind = "deauth" if i % 3 else "disassoc"
        s.add(t, type=kind, bssid=AP, src=AP, dst=dst, channel=36, rssi=-77 + rng.randint(-2, 2),
              reason=7, protected=False)
    s.write("deauth_burst.jsonl", """
37 disconnect frames in under 5 s against the registered AP (unicast to four
stations plus broadcast), received ~35 dB weaker than the AP's beacons.
No reconnects follow. Expected: DEAUTH_BURST (and POSSIBLE_DEAUTH_ATTACK).
""")


def handshake_pattern():
    rng = random.Random(3)
    s = Stream()
    s.beacons(0, 240, rng=rng, every=5.0)
    for i, sta in enumerate(STAS):
        s.connect(2 + i * 3, sta)
    for burst_start in (100.0, 160.0):
        for i in range(24):
            t = burst_start + i * 0.12
            dst = BCAST if i % 6 == 0 else STAS[i % 4]
            s.add(t, type="deauth", bssid=AP, src=AP, dst=dst, channel=36, rssi=-76 + rng.randint(-2, 2),
                  reason=7, protected=False)
        # every affected station reconnects and runs a new 4-way handshake
        for i, sta in enumerate(STAS):
            s.connect(burst_start + 3.5 + i * 1.2, sta, reassoc=True)
    s.write("handshake_pattern.jsonl", """
Disconnect surge -> reconnect -> EAPOL surge, twice: each burst knocks the
four stations off the registered AP; all of them re-authenticate within
seconds. EAPOL entries carry message numbers only (no key material).
Expected: POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT.
""")


def evil_twin():
    rng = random.Random(4)
    s = Stream()
    s.beacons(0, 300, rng=rng, every=5.0)
    for i, sta in enumerate(STAS[:2]):
        s.connect(2 + i * 3, sta)
    # an unregistered BSSID starts advertising the protected SSID with WPA2-PSK only, no PMF
    s.beacons(120, 300, bssid=ROGUE, channel=11, rssi=-35, security=WPA2_ONLY, every=5.0, rng=rng)
    s.add(121, type="probe_resp", bssid=ROGUE, src=ROGUE, dst=STAS[0], ssid=SSID, channel=11, rssi=-35,
          security=WPA2_ONLY)
    s.write("evil_twin.jsonl", """
Same SSID, unknown BSSID, security capability downgrade: a second AP appears
for ExampleSSID with WPA2-PSK only and PMF disabled while the registered AP
advertises WPA2/WPA3 transition with PMF. Expected: POSSIBLE_EVIL_TWIN.
""")


def sensor_flap():
    s = Stream()
    s.beacons(0, 60, every=5.0)
    s.add(20, type="sensor", status="lost", interface="wlx00c0cab85c32")
    s.add(45, type="sensor", status="recovered", interface="wlx00c0cab85c32")
    s.write("sensor_flap.jsonl", "Sensor USB reset at 20 s, back at 45 s. Expected: SENSOR_LOST, SENSOR_RECOVERED.")


def malformed():
    lines = [
        '{"ts":"2026-10-05T06:00:00.000Z","type":"beacon","bssid":"AA:BB:CC:DD:EE:FF","ssid":"ExampleSSID","channel":36,"security":{"akms":["SAE"],"pmf":"required"}}',
        "this is not json",
        '{"ts":"2026-10-05T06:00:01.000Z","type":"deauth","bssid":"not-a-mac"}',
        '{"type":"deauth","bssid":"AA:BB:CC:DD:EE:FF"}',
        '{"ts":"2026-10-05T06:00:02.000Z","type":"warp_drive","bssid":"AA:BB:CC:DD:EE:FF"}',
        '{"ts":"2026-10-05T06:00:03.000Z","type":"deauth","bssid":"AA:BB:CC:DD:EE:FF","channel":4000}',
        "[1,2,3]",
        '{"ts":"2026-10-05T06:00:04.000Z","type":"eapol","bssid":"AA:BB:CC:DD:EE:FF","src":"10:22:33:44:55:01","dst":"AA:BB:CC:DD:EE:FF","eapol_msg":2,"nonce":"redacted-not-real","mic":"redacted"}',
        '{"ts":"2026-10-05T06:00:05.000Z","type":"deauth","bssid":"AA:BB:CC:DD:EE:FF","src":"AA:BB:CC:DD:EE:FF","dst":"10:22:33:44:55:01","reason":7}',
        '{"ts":"2026-10-05T06:00:05.000Z","type":"deauth","bssid":"AA:BB:CC:DD:EE:FF","src":"AA:BB:CC:DD:EE:FF","dst":"10:22:33:44:55:01","reason":7}',
    ]
    path = HERE / "malformed.jsonl"
    path.write_text("# Malformed and duplicate input handling. 3 valid events + 1 duplicate.\n"
                    + "\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {path}")


if __name__ == "__main__":
    normal()
    deauth_burst()
    handshake_pattern()
    evil_twin()
    sensor_flap()
    malformed()
