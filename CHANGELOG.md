# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-05

First public release. Passive, defensive wireless IDS for networks the operator
owns or is authorized to monitor. It never constructs or sends 802.11 frames: no
packet injection, no deauthentication, no credential cracking or recovery.

### Added

- **Passive wireless IDS pipeline**: metadata events → de-duplication → scope
  (protected networks only by default) → detectors → correlation → explained risk
  score → alert manager.
- **Linux sensor discovery** (`sensor list`, `sensor check`): PHYs, drivers, USB
  IDs, bands (2.4 / 5 / 6 GHz), monitor-mode support, regulatory domain,
  NetworkManager state, privileges; read-only, with proof that protected
  interfaces were not changed. Tested with an ALFA MediaTek MT7921U (`mt7921u`).
- **Guarded sensor preparation** (`sensor prepare/release`): monitor mode and
  channel on the dedicated sensor only; protected interfaces (`wlo1`), the
  default-route interface and PHY siblings are refused.
- **Kismet backend**: read-only REST client (system status, datasources, alert
  definitions, alerts, devices with a field allow-list, active logs), optional
  eventbus, optional receive-only frame tap; Kismet WIDS alerts (`DEAUTHFLOOD`,
  `BCASTDISCON`, `DISASSOCTRAFFIC`, `DISCONCODEINVALID`, `DEAUTHCODEINVALID`,
  `APSPOOF`, `ADVCRYPTCHANGE`, `CRYPTODROP`, `CHANCHANGE`) mapped onto Daybreak's
  scoring categories; `kismet config` / `kismet check` helpers.
- **Passive backend**: `AF_PACKET` capture (the socket is only read), radiotap /
  IEEE 802.11 / RSN / WPA / RSNXE metadata parser, guarded channel hopping; pcap /
  pcapng and JSONL replay backends for offline analysis.
- **Deauthentication / disassociation detection**: burst, broadcast, multi-client
  and suspicious-source (RSSI, channel, reason code, PMF) signals.
- **EAPOL anomaly detection**: per-station and per-BSSID reauthentication surges
  from message numbers only.
- **Correlation engine**: `POSSIBLE_DEAUTH_ATTACK`,
  `POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT`, `POSSIBLE_EVIL_TWIN`; every alert lists
  its score components; escalation and cooldown.
- **Protected network registry** (`network add/list/remove`): networks without a
  BSSID stay `unconfigured`; heard BSSIDs are shown as candidates, never adopted.
- **Evil-twin and security-downgrade detection**: unknown BSSID for a protected
  SSID, WPA3 → WPA2, PMF removed, encryption change, channel anomaly,
  incompatible duplicate SSID.
- **WPA / PMF audit** (`audit security`) and passphrase / router hygiene checklist
  (`audit policy`, never asks for the passphrase).
- **Baseline and risk scoring**: robust per-minute rate statistics, learned
  BSSIDs / channels / security / RSSI; risk bands INFO–CRITICAL.
- **Storage and logging**: SQLite (WAL, versioned migrations, retention), JSONL
  and human-readable logs with size rotation.
- **Alerts**: console, JSONL and desktop notifications with cooldown,
  escalation and per-notifier rate limits; extensible notifier interface.
- **CLI** (`daybreak-wids`) with `--dry-run` and `--json`.
- **Local dashboard** (optional extra): read-only, `127.0.0.1` by default.
- **Synthetic regression suite**: 478 tests, synthetic metadata fixtures
  (normal, deauth burst, handshake pattern, evil twin, sensor flap, malformed),
  simulated Kismet API and simulated host; the README's marked example blocks
  are verified against the real CLI.
- `scripts/hardware-smoke-test.sh`: guided passive smoke test for real hardware.
- GitHub Actions workflow (Python 3.10–3.14, synthetic tests only).

### Security

Fixed before release, from an internal review of Daybreak itself (details in
[docs/VALIDATION.md](docs/VALIDATION.md)):

- **Interface guard and commands**: runtime command allow-list in the single
  command runner, which also derives whether a command changes state (so
  `--dry-run` cannot be bypassed) and requires the interface guard's approval for
  every interface-changing command; tools resolved from system directories only,
  minimal child environment; interface names validated; protected interfaces
  pinned at monitor start by name, MAC and PHY; guard and adapter identity
  re-checked before every command; continuous protected-interface verification
  (`PROTECTED_INTERFACE_CHANGED`); `sensor prepare/release --apply` refuse without
  `CAP_NET_ADMIN`, when the adapter's MAC/driver is not the configured sensor's,
  and while the sensor is in use (connected, associated, or in AP / ad-hoc / mesh
  mode); prepare also while a configured protected interface does not exist;
  `sensor.protected_interfaces` may not be empty; the host-command allow-list is
  pinned by a test; automatic re-preparation after a USB reset only for the
  configured sensor, suspended while a protected interface differs from its
  state at start.
- **Kismet**: any HTTP answer at the Kismet URL (e.g. an authentication failure)
  stops instead of falling back to the passive backend; strict URL validation (no
  credentials, query or fragment); credentials only in request headers; neither
  REST nor the eventbus follows redirects or uses an environment proxy (the
  eventbus socket is opened by Daybreak); a warning at monitor start for
  credentials over plain http to another host; `api_key_env` / `password_env`
  must be variable names; anchored endpoint patterns; frame-tap interface names
  validated; the frame-tap state is shown in `monitor status`.
- **Dashboard**: Host allow-list always on (`dashboard.allowed_hosts` with
  `allow_remote`: literal names only, every spelling of the all-interfaces
  address needs it); GET only; at most 16 requests in flight; security headers
  on every response including errors; read-only database access that never
  modifies the database (schema checked, no stale immutable read while a WAL is
  pending); field allow-listed responses; bounded queries that always list the
  registered APs; polling that never overlaps, with request timeouts.
- **Data and privacy**: owner-only runtime files, handed back to the sudo user;
  logs never opened through symbolic links, registry and status written via
  `mkstemp`; symlinked database path refused; `storage.retention_days` enforced
  (database and rotated logs; the WAL is truncated after pruning, or at the next
  prune while another process is reading); SQLite `secure_delete`; event
  metadata limited to scalar values; Kismet alerts attributed only by registered
  BSSID or the whole quoted SSID; control and format characters, line separators
  and lone surrogates (Unicode Cc, Cf, Zl, Zp, Cs) escaped in console, log and
  CLI output; desktop notifications as plain text, never as root (monitor start says
  so), with a minimal environment; notifier options allow-listed, secret-like
  ones refused when the configuration is loaded.
- **Robustness under floods**: detector state, incidents and disconnect
  bookkeeping capped when keys are added (registered BSSIDs and their stations
  are kept), so frozen timestamps cannot grow them either; event rows sampled
  per (event type, BSSID) and, for unregistered BSSIDs, overall; new station
  rows budgeted per registered BSSID and for all others together; new rows for
  unregistered APs budgeted per SSID and, for SSIDs that are not protected,
  overall (detection still sees every event); bounded alert bookkeeping and
  per-type limits for new alerts outside the protected networks; notification
  budgets per severity band; failing alert or status writes counted, never
  fatal; an event whose processing fails is counted and monitoring continues.
- **Untrusted input**: strict, bounded pcap/pcapng parsing; implausible
  timestamps rejected at ingestion and never able to break date formatting of
  stored data; malformed JSONL lines (oversized numbers, infinite values, deep
  nesting) counted instead of aborting a replay; undecodable bytes in replay
  files replaced (U+FFFD), and lines that no longer parse counted as malformed;
  a corrupt capture ends the run with the frames
  before the bad block analysed; lone surrogates cleaned before storage
  (including security-profile strings); hostile Kismet records (non-string
  texts, non-identifier headers, implausible times, NaN / infinite / oversized
  numbers) handled;
  a single far-off timestamp cannot hold a detection window open; failing
  database writes dropped and counted; bounded baseline window and candidate
  list; control characters escaped in the text report.

### Changed (for users of pre-release snapshots)

- A dashboard bound to all interfaces needs `dashboard.allowed_hosts`, which takes
  literal host names or IP addresses only; `/api/alerts` and `/api/status` return
  fewer fields (no summary, station lists, details, PID, config path or backend
  errors).
- `sensor prepare/release` refuse an adapter whose driver differs from
  `sensor.expected_driver` (default `mt7921u`): set it for your adapter.
  `sensor release` refuses a connected sensor.
- Configuration checks that now fail at load: an empty
  `sensor.protected_interfaces`, log file names with a directory part, notifier
  options outside each notifier's allow-list (e.g. JSONL `max_bytes`; use
  `logging.max_bytes`), non-finite detection timings, `detection.baseline.bucket`
  under 10 s.
- Desktop notifications are off when daybreak-wids runs as root.

### Known limitations

- Live capture on real hardware is **not yet verified**: the passive smoke test
  needs root and has not been run (see [docs/VALIDATION.md](docs/VALIDATION.md)).
- **Not verified on a real Kismet server**: the Kismet integration is tested
  against a simulated Kismet REST API only.
- One radio hears one channel at a time; hopping can miss short bursts.
- Kismet-only mode (without the frame tap) cannot correlate handshake capture.
- Thresholds are defaults, not tuned on real attack data; benign roaming, band
  steering, mesh nodes and AP reboots can raise LOW/MEDIUM alerts.
- The dashboard has no authentication (loopback only by default).
- Look-alike SSIDs (trailing NUL, zero-width characters) are not flagged.
- `tests/test_safety.py` is a static tripwire for code review, not a sandbox:
  ordinary code written differently can pass it.
- Within `alerts.cooldown`, a repeat of an alert type for the same network is
  only counted on the earlier alert.

[0.1.0]: https://github.com/<owner>/daybreak-wids/releases/tag/v0.1.0
