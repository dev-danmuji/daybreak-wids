# daybreak-wids

> **Authorized defensive monitoring only.**
> This project does not implement packet injection,
> deauthentication attacks, credential cracking,
> or password recovery.
>
> Use it only on Wi-Fi networks you own or are explicitly authorized to administer.

daybreak-wids is a passive Wireless IDS for WPA2/WPA3 networks. It watches for the
early stages of the classic attack flow against a Wi-Fi network:

1. reconnaissance and rogue/evil-twin access points,
2. attempts to collect a WPA 4-way handshake,
3. abnormal deauthentication / disassociation,
4. the conditions that make an offline dictionary attack possible (weak configuration),

and reports them with an explained risk score. It only ever **receives**: it does
passive detection, configuration auditing, alerting and forensic *metadata*
collection.

| It does | It never does |
|---|---|
| Parse management-frame metadata (addresses, reason codes, RSN/PMF capabilities) | Transmit, inject or replay frames |
| Count EAPOL frames per station/BSSID (message number only) | Store or export handshakes, nonces, MICs, PMKIDs |
| Correlate disconnect bursts with re-authentication | Crack, verify or guess passphrases |
| Audit WPA2/WPA3/PMF/WPS from beacons | Ask for, store or log your Wi-Fi passphrase |
| Raise console / JSONL / desktop alerts | Change AP settings or the internet interface |

## Architecture

```text
ALFA Wi-Fi sensor (wlx00c0cab85c32, MT7921U, monitor mode)
        |
        v
     Kismet  ──────────────── (fallback: built-in receive-only capture)
        |  REST / eventbus          |
        v                           v
  daybreak-wids  ── dedup ── scope ── detectors ── correlator ── alert manager
                     |                 |             |              |
                  SQLite            baseline     risk score    console / JSONL /
                  (metadata)        engine       + reasons     desktop, rotating logs
                     |
                  CLI  ·  optional local dashboard (127.0.0.1)
```

* **Kismet first.** Kismet owns the capture source and channel hopping and already
  implements WIDS alerts (`DEAUTHFLOOD`, `BCASTDISCON`, `DISCONCODEINVALID`,
  `APSPOOF`, `ADVCRYPTCHANGE`, `CRYPTODROP`, `CHANCHANGE`, ...). daybreak-wids
  consumes those alerts and Kismet's AP security records instead of re-implementing
  them, and maps each to the same scoring category as its own detector so a
  phenomenon is counted once. Device records are requested through field
  simplification with an explicit allow-list (no handshake/PMKID fields).
* **Frame tap.** Kismet does not expose per-frame deauth/EAPOL metadata over its API,
  so (optionally, with `CAP_NET_RAW`) daybreak-wids also reads frames from the monitor
  interface Kismet opened, through a receive-only socket.
* **Fallback.** Without Kismet the built-in passive backend reads the monitor-mode
  sensor directly (receive-only `AF_PACKET`), with guarded channel hopping over the
  protected networks' channels.
* **Offline.** `--replay file.jsonl` (metadata streams, used by the tests) and
  `--pcap file.pcapng` (existing captures, read-only) run the same pipeline.

## Install

```bash
cd daybreak-wids
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'            # core + tests
.venv/bin/pip install -e '.[dashboard]'      # optional dashboard (FastAPI)
.venv/bin/pip install -e '.[eventbus]'       # optional Kismet eventbus (websocket)
cp config.example.yaml config.yaml           # then edit protected_networks
```

Python ≥ 3.10, Linux with `iw`; NetworkManager (`nmcli`) is optional.

## Quick start

```bash
daybreak-wids sensor list          # PHYs, drivers, bands, monitor support, NM state
daybreak-wids sensor check         # readiness of the ALFA sensor; proves wlo1 is untouched
daybreak-wids network add --name home --ssid ExampleSSID \
    --bssid AA:BB:CC:DD:EE:FF --channel 36 --expect WPA2 --expect WPA3 --pmf capable
daybreak-wids monitor start        # Kismet if reachable, else the passive backend
daybreak-wids alerts --details
daybreak-wids report
```

Without hardware, replay the synthetic fixtures:

```bash
daybreak-wids -c config.yaml monitor start --replay tests/fixtures/handshake_pattern.jsonl
daybreak-wids -c config.yaml --dry-run monitor start --replay tests/fixtures/evil_twin.jsonl
```

### Example output

```text
2026-10-05 15:01:43 CRITICAL POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT
Network=home SSID=ExampleSSID
BSSID=AA:BB:CC:DD:EE:FF
Channel=36
Frames=22/5s
AffectedStations=4
Risk 95 CRITICAL
+30 deauth burst (22 frames/5s, threshold >10)
+20 broadcast disconnect (3 broadcast/multicast frames in 60s)
+15 suspicious source (3 frames claiming AA:BB:CC:DD:EE:FF: RSSI -76 dBm vs AP -40±1 dBm)
+15 multiple stations affected (3 stations in 30s)
+5 burst intensity (2.2x threshold)
+10 disconnected stations re-authenticated (1 station(s), EAPOL 1.1s after disconnect)
Summary=Disconnect burst followed by re-authentication of the affected stations: consistent with
an attempt to capture a WPA handshake. Whether a handshake was obtained is not determined.
```

## Sensor setup

The sensor is a dedicated adapter (default `wlx00c0cab85c32`, MediaTek MT7921U,
driver `mt7921u`, 2.4/5/6 GHz). The internet interface (`wlo1`) is listed in
`sensor.protected_interfaces` and is never modified: any command that would touch a
protected interface, an interface carrying the default route, or an interface on the
same PHY is refused, and protected interfaces are snapshotted before and verified after
every sensor operation (`sensor check`, `sensor prepare`, `monitor start`).

### Option A: Kismet (recommended)

```bash
sudo apt install kismet
daybreak-wids kismet config        # prints a kismet_site.conf snippet: source, apspoof rules,
                                   # and enable_logging=false (Kismet logs can contain handshakes)
# add the snippet to /etc/kismet/kismet_site.conf, start Kismet, then in the Kismet web UI
# create an API key with the *readonly* role:
export KISMET_API_KEY=...
daybreak-wids kismet check         # reachability, datasource, which WIDS alerts exist
daybreak-wids monitor start
```

daybreak-wids itself does not need root with Kismet. For per-frame metadata (deauth
reason codes, EAPOL message counts, beacon RSN parsing) it also taps Kismet's monitor
interface, which needs `CAP_NET_RAW`; without it, detection relies on Kismet's WIDS
alerts and AP records (`kismet check` / `monitor status` show which mode is active).

### Option B: built-in passive backend

```bash
daybreak-wids sensor prepare --channel 36          # prints the plan only
sudo daybreak-wids sensor prepare --apply --channel 36
sudo daybreak-wids monitor start --backend passive
sudo daybreak-wids sensor release --apply          # back to managed mode / NetworkManager
```

`prepare` runs only `nmcli device set <sensor> managed no`, `ip link set <sensor>
down|up`, `iw dev <sensor> set type monitor` and `iw dev <sensor> set channel N`
(an allow-list enforced by tests). After a USB reset the adapter usually returns in
managed mode and NetworkManager may manage it again; with `sensor.auto_prepare: true`
monitor mode is restored on the **sensor only**. To keep NetworkManager away
permanently, `sensor check` prints the `unmanaged-devices=mac:...` line to add yourself
(daybreak-wids never edits system configuration).

Run all commands as the same user so the database stays writable.

## Detection

| Finding (individual alert) | Default points | Trigger |
|---|---|---|
| `DEAUTH_BURST` | 30 | more than 10 deauth/disassoc frames in 5 s for one BSSID |
| `BROADCAST_DEAUTH` | 20 | ≥ 3 broadcast/multicast disconnects in 60 s |
| `MULTI_CLIENT_DEAUTH` | 15 | ≥ 3 distinct stations disconnected in 30 s |
| `SUSPICIOUS_SOURCE` | 15 | ≥ 3 frames claiming the AP but with deviating RSSI, wrong channel, invalid reason code, or unprotected on a PMF-required network |
| `INVALID_REASON_CODE` | 5 | reserved reason code |
| `EAPOL_REAUTH_SURGE` | 17 | ≥ 3 handshakes or ≥ 12 EAPOL frames per station/60 s; ≥ 4 stations or ≥ 40 frames per BSSID/60 s |
| `UNKNOWN_BSSID_FOR_PROTECTED_SSID` | 30 | an unregistered BSSID advertises a protected SSID (a warning, not a verdict) |
| `SECURITY_DOWNGRADE` | 30 | e.g. WPA3 → WPA2, below the registry expectation or the registered AP |
| `PMF_DOWNGRADE` | 15 | PMF required/capable → weaker |
| `ENCRYPTION_CHANGE` | 15 | other capability change on a registered BSSID |
| `CHANNEL_ANOMALY` | 10 | channel outside the registry/baseline |
| `INCOMPATIBLE_DUPLICATE_SSID` | 20 | same SSID with disjoint security (e.g. open vs WPA2) |
| `BASELINE_DEVIATION` | 9–15 | rate far above the learned median *and* above the learned maximum |
| `KISMET_<HEADER>` | category weight | Kismet WIDS alert, mapped to the same category as above |

| Correlated alert | Combination |
|---|---|
| `POSSIBLE_DEAUTH_ATTACK` | burst/broadcast disconnects plus another disconnect signal (or ≥ 50 points) |
| `POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT` | deauth burst + station disconnect + EAPOL activity *after* it (surge or re-authentication of the same stations) |
| `POSSIBLE_EVIL_TWIN` | unknown BSSID + weaker/incompatible security from that BSSID, or one BSSID alternating between profiles; concurrent deauth adds points |
| `SENSOR_LOST` / `SENSOR_RECOVERED` | adapter disappeared/returned (same MAC, possibly new name) or Kismet datasource failed |

Scores add up, are capped at 100 and are always printed with their components.
Bands: 0–29 INFO, 30–49 LOW, 50–69 MEDIUM, 70–89 HIGH, 90–100 CRITICAL. All weights
and thresholds are configurable (`scoring.weights`, `detection.*`). A single deauth
frame never raises an alert; composite alerts never claim that an attack succeeded.

**Baseline.** `daybreak-wids baseline create` (live for `--duration`, from `--replay` /
`--pcap`, or `--from-db`) learns per-minute disconnect/EAPOL/connection rates (median,
MAD, p95, max), registered BSSIDs, channels, security capabilities, per-BSSID RSSI and
the client-count range. Learn during a period without known attacks.

**Alerts.** Repeats of the same alert type for the same network are suppressed for
`alerts.cooldown` seconds unless the score rises by `escalation_delta` or the severity
increases; the next alert reports how many were suppressed. Human-facing notifiers are
also rate limited per minute.

## Audits

```bash
daybreak-wids audit security       # WPA2/WPA3 transition, PMF capable/required, WPS, ciphers
daybreak-wids audit policy         # passphrase / router hygiene checklist (no PSK input)
```

```text
SSID: ExampleSSID

WPA2/WPA3 Transition : enabled
PMF                  : capable
PMF required         : no

Recommendation:
  Consider WPA3-SAE + PMF required if every client supports it.
```

## Data, logs and privacy

* SQLite (`storage.database`): `networks`, `aps`, `stations`, `events`, `alerts`,
  `baselines`, `sensor_status`; schema versioned with `PRAGMA user_version`.
* Event metadata passes an allow-list; keys such as `nonce`, `mic`, `pmkid`,
  `key_data`, `replay_counter`, `passphrase`, raw frames and EAP identities are dropped
  before storage. Beacons are summarised in `aps`, not stored per frame. With the default
  `detection.scope: protected`, frames of neighbouring networks are not analysed or stored.
* Logs (`logging.directory`): human-readable `daybreak.log` and `alerts.jsonl`, both
  size-rotated (`max_bytes`, `backup_count`).

## Dashboard (optional)

```bash
daybreak-wids dashboard            # http://127.0.0.1:8765/
```

Read-only (GET only), binds to loopback by default, rejects non-loopback `Host`
headers (DNS rebinding), strict CSP, no external resources. Panels: sensor, protected
networks, current alerts, event timeline, AP security, baseline, threat level.

## Safety model

* `safety.passive_only: true`, `packet_injection: false`,
  `transmit_management_frames: false` are declarations; any other value refuses to start.
  There is no transmit code path to enable.
* `tests/test_safety.py` checks the source (AST) of every module: no injection/crafting
  libraries, no send/write on raw sockets (only `sensor/passive.py` may open one, and it
  exposes receive operations only), no deauth frame templates, no attack tools, no key
  derivation/MIC verification, no handshake export formats, no binary file writes, no
  password-guessing code, no passphrase input, and only allow-listed host commands.
* Tests themselves cannot open packet sockets or run `iw`/`ip`/`nmcli`.

## Testing

```bash
.venv/bin/python -m pytest
python tests/fixtures/make_fixtures.py      # regenerate the synthetic fixtures
```

Fixtures (`tests/fixtures/*.jsonl`) are synthetic metadata streams — no captured
frames or key material:

| Fixture | Expected |
|---|---|
| `normal.jsonl` | no HIGH alert |
| `deauth_burst.jsonl` | `DEAUTH_BURST` (+ `POSSIBLE_DEAUTH_ATTACK`) |
| `handshake_pattern.jsonl` | `POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT` |
| `evil_twin.jsonl` | `POSSIBLE_EVIL_TWIN` |
| `sensor_flap.jsonl` | `SENSOR_LOST`, `SENSOR_RECOVERED` |
| `malformed.jsonl` | malformed lines skipped, key-material fields stripped, duplicate suppressed |

## Extending notifiers

Console, JSONL and desktop (`notify-send`) are built in. Slack, Discord, Telegram,
e-mail or webhooks can be added by registering a `Notifier` subclass
(see `daybreak/alerts/base.py`) and listing it under `alerts.notifiers`.

## Limitations

* Live capture on the ALFA adapter needs Kismet or root/`CAP_NET_RAW`; the test suite
  exercises the capture code with synthetic frames only.
* Kismet-only mode (no frame tap) cannot count EAPOL frames or per-frame reason codes;
  handshake-capture correlation needs the frame tap or the passive backend.
* Encrypted (PMF-protected) unicast deauth frames hide their reason code; that is
  expected and reported as protected.
* A single radio sees one channel at a time; with several protected channels the
  passive backend hops and can miss short bursts on the other channel.
* 6 GHz channel numbers overlap 2.4 GHz numbers; channel expectations in the registry
  refer to 2.4/5 GHz numbering (frequencies are recorded in event metadata).
* RSSI deviation and channel checks are heuristics; an attacker close to the sensor or
  on the AP's channel is not distinguishable by RSSI alone.
* Desktop notifications need a desktop session; a root process usually cannot reach it.

## Layout

```text
daybreak/
  cli.py  config.py  models.py  safety.py  registry.py  pipeline.py  runtime.py
  monitor.py  report.py  scoring.py  policy.py
  sensor/      discovery, check, control (guarded), status (health), backend, kismet,
               passive (receive-only), pcapfile, replay, select
  dot11/       ieee80211 constants, frames (radiotap/802.11 metadata), rsn (RSN/WPA/RSNXE)
  detectors/   deauth, eapol, spoof, security (audit), kismet_alerts, window, base
  correlation/ engine
  baseline/    engine
  alerts/      manager, base (registry), console, jsonl, desktop, formatting
  storage/     database, migrations
  dashboard/   app (FastAPI), static/
tests/         unit + integration tests, fixtures/
```

License: MIT (see `LICENSE`).
