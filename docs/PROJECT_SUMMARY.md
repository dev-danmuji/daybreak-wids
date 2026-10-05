# Daybreak WIDS: project summary

A passive, defensive wireless intrusion detection system for Linux, written in
Python, for Wi-Fi networks the operator owns or is authorized to monitor.
Status: v0.1.0, 478 automated tests; live capture on real hardware and a
real Kismet server are not yet verified (see [VALIDATION.md](VALIDATION.md)).

## Problem

Deauthentication and disassociation frames end Wi-Fi connections. Without Protected
Management Frames they are unauthenticated, so they can be forged to knock clients
offline and to force the reconnections that expose a WPA2-Personal (PSK) 4-way
handshake to offline guessing. The same frames are part of normal operation:
roaming, idle timeouts, AP reboots and band steering all produce them. A single
deauthentication frame is therefore not evidence of an attack, and a detector that
alerts on one is mostly noise.

## Approach

Daybreak only receives frames and combines several weak, passive signals into
one explained score:

- per-BSSID disconnect bursts, broadcast disconnects, many stations disconnected
  at once, and frames whose signal strength, channel, reason code or protection
  does not match the real AP;
- EAPOL activity (message numbers only) that *follows* a disconnect burst, or
  re-authentication of the stations that were just disconnected;
- unregistered BSSIDs advertising a protected SSID with weaker or incompatible
  security (WPA3 → WPA2, PMF removed, different channel);
- deviation from a learned baseline of the network's normal rates.

Single attack-detection signals stay in the INFO/LOW bands by default; only
correlated incidents (`POSSIBLE_DEAUTH_ATTACK`,
`POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT`, `POSSIBLE_EVIL_TWIN`) can reach HIGH or
CRITICAL, and with few signals they stay LOW or MEDIUM (a WPA2-only twin of a
WPA2/WPA3 network scores 60, MEDIUM). Every alert lists its score components. Alerts
describe patterns; they do not claim that an attack succeeded or identify who sent
the frames.

## Defensive scope

- **Passive monitoring.** Receive-only capture; no transmit, injection or
  replay path exists in the code.
- **Anomaly detection** on management-frame and EAPOL metadata.
- **Configuration audit** of WPA2 / WPA3-SAE / transition mode / PMF / WPS from
  beacons, plus a passphrase hygiene checklist that never asks for the passphrase.
- **Forensic metadata** in SQLite and JSONL: addresses, reason codes, message
  numbers, security capabilities; no payloads, handshakes, nonces, MICs, PMKIDs
  or passphrases.
- **No offensive capabilities** by design: no transmit path, one capture
  socket that is only read, one command runner with a runtime allow-list; static
  tests are a tripwire for code review.

## Engineering

| Area | Implementation |
|---|---|
| Language / packaging | Python 3.10+ (tested 3.10–3.14), setuptools, `click` CLI, `PyYAML` strict config loader; optional FastAPI dashboard and websocket eventbus extras |
| Size | 10,174 lines of Python in the `daybreak` package (plus 524 lines of dashboard HTML/JS/CSS), 5,820 lines of Python under `tests/` |
| Capture backends | Kismet REST + eventbus client (read-only endpoints, field allow-list, readonly API key, optional receive-only frame tap); built-in `AF_PACKET` backend (socket only read) with guarded channel hopping; pcap / pcapng reader; JSONL replay |
| Frame parsing | Own radiotap, IEEE 802.11 management/data, RSN / WPA / RSNXE parser; EAPOL message number inferred from the 2-byte Key Information field only |
| Detection | Sliding windows with hysteresis triggers; size-capped per-station and per-BSSID state with idle eviction (registered BSSIDs never evicted); AP security-profile comparison against the registry, the baseline and the AP's own history |
| Correlation | Per-BSSID and per-network incidents; each category counted once (Kismet alerts map onto the same categories); re-emission only on score escalation |
| Baseline | Robust statistics (median, MAD, p95, max) of per-minute rates, plus learned BSSIDs, channels, security and signal levels |
| Storage | SQLite (WAL, versioned migrations, retention, `secure_delete`), owner-only files, rotating JSONL and human-readable logs |
| Interfaces | CLI with `--dry-run` / `--json`; read-only localhost dashboard (Host allow-list, CSP, field allow-listed responses) |
| Safety engineering | Interface guard (protected interfaces, default-route interface and PHY siblings refused; identity re-checked before every command; continuous verification while monitoring), runtime command allow-list, AST-based static safety tests |
| Tests | 478 tests: synthetic frames and fixtures, a simulated Kismet server, a simulated host (sysfs, `iw`, `nmcli`), README output verification; during the run, `AF_PACKET` sockets and `subprocess.run` calls to network tools are refused |
| Hardware | LattePanda 3 Delta (Ubuntu 26.04.1 LTS, Linux 7.0) with an ALFA USB adapter, MediaTek MT7921U (`mt7921u`), 2.4 / 5 / 6 GHz |

## Validation

What has actually been verified (details and dates in [VALIDATION.md](VALIDATION.md)):

- The automated suite passes on Python 3.10, 3.11, 3.12, 3.13 and 3.14 in clean
  environments, together with a byte-compile check and a synthetic demo replay.
- On the tested host, sensor discovery and readiness checks identify the ALFA
  adapter correctly (phy, driver, USB ID, bands, monitor support, regulatory
  domain, NetworkManager state), read-only, and the internet interface `wlo1` is
  unchanged before and after.
- The guarded sensor-preparation plan targets only the sensor adapter and is
  refused for protected interfaces (simulated host tests and the real host's
  printed plan).
- An internal security review of Daybreak itself (dashboard, process and
  privilege model, secrets and privacy, untrusted-input parsing, transmit path),
  with adversarial verification of each finding; the fixes are covered by
  regression tests.

Not verified yet: live passive capture on the ALFA adapter in monitor mode (it
needs root; a guided script is provided) and integration with a real Kismet
server (tested against a simulated Kismet API only). No detection-rate or
false-positive figures are claimed.

## Safety

- Daybreak never constructs or sends 802.11 frames: no packet injection, no
  deauthentication, no handshake capture or export, no cracking, no credential
  recovery, no password guessing.
- The configuration's safety block (`passive_only: true`, `packet_injection:
  false`, `transmit_management_frames: false`) is a declaration; other values
  refuse to start.
- Only the dedicated sensor adapter is ever reconfigured (monitor mode, channel),
  and only on request; the operator's internet interface is protected by name,
  route, PHY and MAC.

## Limitations

- Real-hardware and real-Kismet validation are incomplete (see above).
- One radio hears one channel at a time; hopping across channels can miss bursts.
- Without the frame tap, the Kismet backend cannot count EAPOL frames, so the
  handshake-capture correlation needs the frame tap or the passive backend.
- Signal-strength and channel heuristics cannot separate a forger that is close
  to the sensor or on the AP's channel; RF jamming is not detected.
- Thresholds are defaults, not tuned on real attack data; benign roaming, AP
  reboots, band steering and mesh nodes can produce LOW/MEDIUM alerts.
- The dashboard has no authentication (loopback only by default).
