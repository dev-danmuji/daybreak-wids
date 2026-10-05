# Validation

What has been verified for Daybreak WIDS v0.1.0, how, and what has not.
Only results that were actually produced are listed; nothing here is
extrapolated. Date of all runs: 2026-10-05.

## Environment

| | |
|---|---|
| OS | Ubuntu 26.04.1 LTS (Resolute Raccoon) |
| Kernel | 7.0.0-38-generic |
| Hardware | LattePanda 3 Delta (Intel Celeron N5105) |
| Sensor | ALFA USB Wi-Fi adapter (MAC OUI `00:C0:CA`), MediaTek MT7921U chipset, USB ID `0e8d:7961`, interface `wlx00c0cab85c32` on `phy3`; bands 2.4 / 5 / 6 GHz; monitor mode listed in `iw phy` |
| Driver | `mt7921u` (in-tree driver of the kernel above) |
| Regdomain | KR (`iw reg get`: global `country KR: DFS-JP`; `phy#0` self-managed KR) |
| Internet interface | `wlo1` (`phy0`, `iwlwifi`, PCI): connected, carries the default route; configured as protected |
| Host tools | iw 6.17, iproute2 6.19.0, NetworkManager / nmcli 1.54.3, sudo-rs 0.2.13 |

## Automated Tests

| | |
|---|---|
| Total | 478 |
| Passed | 478 |
| Failed | 0 |
| Before this release work | 296 collected, 296 passed (Python 3.14.4, development venv) |

The same suite was run in clean environments (fresh virtualenv per version, the
package installed from a clean copy of the repository with
`pip install -e '.[dev,dashboard,eventbus]'`), together with the steps of the
GitHub Actions workflow (non-root check, `python -m compileall daybreak`, a
dry-run replay of `tests/fixtures/handshake_pattern.jsonl` that must print
`CRITICAL POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT`):

| Python | Result |
|---|---|
| 3.10.22 | PASS: 478 passed, 0 failed; byte-compile, non-root check and demo replay OK |
| 3.11.17 | PASS: 478 passed, 0 failed; byte-compile, non-root check and demo replay OK |
| 3.12.3 | PASS: 478 passed, 0 failed; byte-compile, non-root check and demo replay OK |
| 3.13.16 | PASS: 478 passed, 0 failed; byte-compile, non-root check and demo replay OK |
| 3.14.4 | PASS: 478 passed, 0 failed; byte-compile, non-root check and demo replay OK |

Dependency versions in those environments: PyYAML 6.0.3, click 8.5.0, fastapi
0.142.2, starlette 1.7.0, uvicorn 0.54.0, websocket-client 1.9.2, pytest 9.1.1,
httpx 0.28.1. Each run took 21–26 s. GitHub Actions itself has not run yet (no
remote repository exists); the workflow file mirrors the steps above.

The suite uses no live hardware: synthetic 802.11 frames and radiotap headers,
synthetic metadata fixtures, a simulated Kismet REST server (loopback HTTP), and a
simulated host (a sysfs tree plus `iw` / `nmcli` output captured verbatim on the
test host, with the internet interface's MAC address and SSID anonymised).
During the run `tests/conftest.py` refuses `AF_PACKET` sockets at construction and
`subprocess.run` calls to `iw`, `ip`, `nmcli`, `rfkill`, `notify-send`,
`airmon-ng` and `kismet`.

## Real Sensor Smoke Test

| | |
|---|---|
| Status | **NOT RUN** (blocked: no root in the session that prepared this release) |
| Date | 2026-10-05 |
| Interface | `wlx00c0cab85c32` |
| Channel | 149 (planned: the operator's 5 GHz access point) |

Live capture needs monitor mode (`CAP_NET_ADMIN`) and a packet socket
(`CAP_NET_RAW`). The release was prepared in a session where `sudo` required
interactive authentication (`sudo -n true` → "interactive authentication is
required"), so `sensor prepare --apply` and `monitor start --backend passive`
were not executed, and no frames were captured. No privilege workaround was used.

Verified on the real host, read-only:

- **Pre-flight**: `wlo1` connected and carrying the default route; ALFA present
  on `phy3`, managed mode, NetworkManager state `disconnected`; regdomain KR.
  Raw output is kept locally under `var/validation/` (git-ignored, contains the
  operator's own SSID and MAC addresses).
- **`daybreak-wids sensor list`**: `wlo1` → `phy0`, `iwlwifi`, role
  "protected (never modified)"; `wlx00c0cab85c32` → `phy3`, `mt7921u`,
  `usb 0e8d:7961`, bands 2.4/5/6, monitor yes, role "sensor".
- **`daybreak-wids sensor check`**: presence, driver, isolation (dedicated
  adapter: not protected, no default route, separate PHY), monitor support,
  bands and regdomain OK; warnings for NetworkManager managing the sensor and
  Kismet not reachable; "protected-interfaces: unchanged (wlo1)".
- **`daybreak-wids sensor prepare --channel 149`** (plan only, not executed):
  `nmcli device set wlx00c0cab85c32 managed no`, `ip link set wlx00c0cab85c32
  down`, `iw dev wlx00c0cab85c32 set type monitor`, `ip link set
  wlx00c0cab85c32 up`, `iw dev wlx00c0cab85c32 set channel 149`; no command
  names `wlo1`.
- **`scripts/hardware-smoke-test.sh run`** up to its first privileged step, with
  `sudo` replaced by a stub that refuses every call: pre-flight passed, the
  protected-interface record (NetworkManager state, operstate, interface type,
  link flags, default route) was taken before and compared after, the script
  attempted to release the sensor and stopped; nothing was changed. Invalid
  input (non-numeric channel, missing configured network) is refused.
- **`wlo1`** was connected, with the same default route, before and after all
  work in this session.

To complete this section (operator, on a network you own):

```bash
cp config.example.yaml config.yaml          # replace the example network: your SSID, channel 149 and, if known, its BSSID
scripts/hardware-smoke-test.sh discover     # if the BSSID is unknown: lists BSSIDs heard for your SSID (nothing adopted);
                                            # register yours with `network add --replace ... --bssid`
scripts/hardware-smoke-test.sh run          # needs SSID + BSSID on channel 149; 300 s passive run; reconnect one of your own devices
```

Then record from `var/validation/<timestamp>-run/summary.txt` (counts only):

| | |
|---|---|
| Monitor mode | (from `prepare.txt` / `sensor-after-prepare.txt`) |
| Frames observed | (events stored by type) |
| Normal reconnect observed | (auth / assoc / reassoc / EAPOL events at the reconnect) |
| False HIGH alert | (HIGH/CRITICAL alerts: expected 0) |
| `wlo1` affected | (invariant checks: expected unchanged) |
| Sensor recovery | (optional unplug/replug: `SENSOR_LOST` then `SENSOR_RECOVERED`) |

## Kismet Integration

| | |
|---|---|
| Status | **NOT VERIFIED ON REAL KISMET** |
| Installed | no: the Ubuntu 26.04 archive has no `kismet` package; it would have to come from the Kismet project's own packages, which needs root |

Covered by the simulated Kismet server (`tests/kismet_fake.py`,
`tests/test_kismet.py`):

- REST: system status and server time, datasource list, alert definitions,
  alerts since a timestamp, devices since a timestamp, active logs; only these
  allow-listed endpoints are requested.
- Authentication: readonly API key as cookie; HTTP 401 → clear error; in
  `backend.type: auto` any HTTP answer at the Kismet URL (e.g. an authentication
  failure) stops instead of falling back to the passive backend; the REST client
  refuses HTTP redirects.
- Device records: the field allow-list is sent with the request, and extra
  fields injected by the server (e.g. a handshake list with nonces) are dropped
  on receipt.
- Eventbus: subscription, message queueing, reconnect; credentials sent as
  headers, never in the URL; re-opening the backend replaces the eventbus reader
  (no duplicate reader thread). End to end over loopback, with `http_proxy` set
  and a server that answers with a redirect: nothing reaches the proxy or the
  redirect target, and the connection is refused.
- Hostile Kismet records: non-string texts, non-identifier alert headers,
  implausible timestamps, infinite frequencies and packet counts are dropped or
  replaced, never fatal.
- Backend restart: Kismet unavailable mid-run → `BACKEND_UNAVAILABLE`, retry with
  backoff, recovery; a failing Kismet datasource → `SENSOR_LOST`.
- Fallback: Kismet unreachable in `auto` mode → built-in passive backend.
- `kismet check` and `kismet config` output.

Not covered: field names and alert texts of real Kismet releases, eventbus
cookie authentication against a real server, TLS (`https`/`wss`) against a real
server, and the frame tap on the monitor interface Kismet creates.

To verify (operator):

```bash
# install Kismet from the Kismet project's packages (Ubuntu 26.04 has no kismet package)
daybreak-wids -c config.yaml kismet config      # review, then add to /etc/kismet/kismet_site.conf
# start Kismet, create a readonly API key in its web UI, then:
export KISMET_API_KEY='...'
daybreak-wids -c config.yaml kismet check
daybreak-wids -c config.yaml monitor start --backend kismet --duration 300      # Kismet-only mode
sudo --preserve-env=KISMET_API_KEY .venv/bin/daybreak-wids -c config.yaml \
    monitor start --backend kismet --duration 300                              # with the frame tap (CAP_NET_RAW)
daybreak-wids -c config.yaml monitor status     # the backend line says whether the frame tap was active
```

## Safety Verification

**Static checks** (`tests/test_safety.py`, over the AST of every module) look
for literal forms of: packet-crafting or injection libraries; send/write calls
in the module that handles raw sockets (only `sensor/passive.py` mentions them);
deauthentication frame templates; attack-tool names; key derivation or MIC
verification; handshake export formats and binary file writes; password-guessing
code; passphrase options in the CLI or configuration; literal host command lines
outside the allow-list that `CommandRunner` enforces at runtime. The operator
script is checked with patterns for interface-changing tools, attack tools and
`sudo` use, and `tests/test_hardening.py` pins the runtime command allow-list
itself. The review showed that ordinary code written differently (numeric
socket constants, computed attribute names, tuple command lines, other
subprocess helpers, `Path.open("wb")`, `hashlib.scrypt`) passes these checks:
they are a tripwire for code review, not a sandbox. What the package actually
does is pinned down by its structure: one capture socket that is only read, one
command runner that enforces the allow-list and the interface guard, and no
other subprocess use except the desktop notifier.

**Runtime guard** (simulated host): the plan and every command target only the
sensor; protected interfaces, the default-route interface and PHY siblings are
refused; name aliases (`wlo1/`, `./wlo1`, option-like names) are refused; the
protected set stays pinned when the default route moves or an interface is
renamed; a different adapter that takes the sensor's name is refused; commands
stop if the interface changes identity mid-plan; `--apply` is refused without
`CAP_NET_ADMIN`, for an adapter whose driver or MAC is not the configured
sensor's, and for a sensor that is in use (connected, associated, or in AP /
ad-hoc / mesh mode) by both `prepare` and `release`; `prepare` is also refused
when a configured protected interface does not exist; the live monitor raises
`PROTECTED_INTERFACE_CHANGED` and suspends automatic re-preparation until the
interface is back (status record `PROTECTED_RESTORED`).

**Real host**: the read-only checks listed under *Real Sensor Smoke Test*.

**Security review of Daybreak itself** (before release): five independent
reviews (local dashboard; subprocess / privilege / interface guard; secrets,
logging and privacy; untrusted-input parsing; transmit path and static-test
coverage), followed by an adversarial verification of the fixes.

| Review | Confirmed findings | Medium | Low | Info |
|---|---|---|---|---|
| Local dashboard | 6 | 2 | 3 | 1 |
| Subprocesses, privileges, interface guard | 19 | 6 | 8 | 5 |
| Secrets, logging, privacy | 9 | 4 | 4 | 1 |
| Untrusted-input parsing | 11 | 4 | 6 | 1 |
| Transmit path, static-test coverage | 13 | 0 | 12 | 1 |
| **Total** | **58** | **16** | **33** | **9** |

Every finding was reproduced before it was accepted; none was rated high or
critical. No review found a transmit path, a way to change the internet
interface under the default configuration, or key material being stored.

The fixes came in two rounds. Round one (commits `0a631b6` to `20c4a15`) was
checked by a second, adversarial pass that re-ran each scenario against the
code and tried to bypass the fix: 26 findings fixed, 19 partly fixed, 1 not
fixed, and 12 accepted ones re-examined. That pass also found 41 follow-up
issues: regressions introduced by the fixes (for example, the eventbus
resending the Kismet key on a redirect once credentials moved into headers)
and new issues (for example, wildcard `allowed_hosts`, environment proxies
used by websocket-client, and unbounded per-BSSID detector state). Round two
(commits `b5f54ec` to `d7cc837`) fixed the partial and follow-up items. Each
fix comes with a regression test in `tests/test_hardening.py` that was checked
to fail against the code before the fix.

A final review of the round-two commits found no violation of the safety
invariants: nothing constructs or sends frames, every new check refuses more
rather than less, and Kismet credentials reach only the Kismet host. It reported
two medium issues (expiry every 10,000 events made CPU grow quadratically under
a silent random-BSSID flood; EAPOL frames from random BSSIDs could flush a
protected client's per-station state and hide a station-level surge) and six
low or informational ones (a storage budget that could starve a rogue AP's row,
a WAL checkpoint that could stall the monitor for 10 s, unguarded sensor-status
writes, NaN / oversized Kismet numbers, a wrong candidate count, and Unicode
format characters left unescaped). All were fixed in `579dc29`, each with a
regression test that fails without the fix.

Two fact-checks of README.md and the documents in `docs/` against the code
(about 400 claims) led to the corrections in this release's documentation.

Accepted and documented instead of changed:

- the static safety tests are a tripwire for code review, not a sandbox;
- the active log file can hold lines older than `retention_days` until it rotates;
- the built-in defaults name the tested host's adapters (sensor
  `wlx00c0cab85c32`, protected `wlo1`); elsewhere they fail closed, and the
  sensor adapter's MAC stays in the example configuration as the documented
  test adapter;
- distinct decoy alerts can use up one severity band's console/desktop budget
  (the alerts are still stored and logged);
- look-alike SSIDs are treated as different networks.

Fuzzing during the review used scratch harnesses that are not part of the
repository. About 1.14 million mutated pcap/pcapng files, 2.05 million frames
and 532,000 JSONL lines went through the parsers, and nothing escaped except
the documented format errors (`CaptureFormatError`, and malformed lines that
are counted). A run with 147,000 mutated Kismet records found uncaught
`OverflowError` / `ValueError` on infinite or non-numeric fields; round two
fixed that (`test_kismet_numeric_fields_are_range_checked`). The final review's
own fuzzing (300,000 mutated frames through the frame parser and the pipeline,
20,000 mutated capture files) found no crash.

## Known Limitations

- Live capture on the ALFA adapter in monitor mode has not been run (see above);
  frame parsing is verified with synthetic frames only.
- Not verified on a real Kismet server (see above).
- Whether `sudo-rs` passes `SUDO_UID` / `SUDO_GID` (used to hand runtime files
  back to the invoking user) is not verified on this host; the smoke-test script
  reports the database owner and hands `var/` back itself.
- GitHub Actions has not run yet; the identical steps pass locally on Python
  3.10–3.14.
- No detection-rate or false-positive-rate figures exist: there is no labelled
  real-world dataset, and thresholds are defaults.
- One radio hears one channel at a time; Kismet-only mode (no frame tap) cannot
  correlate handshake capture.
- The README animation (`docs/animation/`) has not been rendered: Manim and
  ffmpeg are not installed on the machine that prepared this release, and
  nothing was installed for it. Its source, render script and commands are in
  `docs/animation/`.
- The fuzzing done during the review used a scratch harness that is not part of
  the repository; its figures cannot be reproduced from the repository alone.
