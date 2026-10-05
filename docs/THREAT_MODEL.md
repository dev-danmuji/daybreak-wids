# Threat model

Daybreak WIDS is a passive, defensive wireless intrusion detection system for
Wi-Fi networks its operator owns or is authorized to monitor. This document
states what it protects, which threats it observes, what it deliberately does
not try to do, where its trust boundaries are, and which benign situations look
like attacks.

## Assets

| Asset | Why it matters |
|---|---|
| Protected Wi-Fi network (registered SSID + BSSIDs) | The thing being monitored; only registered networks are analysed by default |
| AP identity | Clients trust an SSID; an unregistered BSSID with the same SSID can attract them |
| Client connectivity | Forged disconnects deny service and force reconnects |
| Wireless security configuration | WPA2 / WPA3-SAE / transition mode / PMF / WPS determine which attacks are possible at all |
| The operator's internet link (`wlo1` on the tested host) | Must keep working while a separate adapter is used as the sensor |
| Daybreak's own data | The database and logs contain MAC addresses, SSIDs and alert history (personal data) |

## Observed threats

What Daybreak looks for, and the evidence it uses. All of it comes from frames
received by the sensor, Kismet's WIDS alerts, or Kismet's AP records.

| Threat | Observable evidence | Daybreak signal |
|---|---|---|
| Deauthentication abuse | burst of deauth frames for one BSSID, frames to broadcast, many stations hit in a short window, frames whose RSSI/channel/reason code does not match the real AP, unprotected frames on a PMF-required network | `DEAUTH_BURST`, `BROADCAST_DEAUTH`, `MULTI_CLIENT_DEAUTH`, `SUSPICIOUS_SOURCE`, `INVALID_REASON_CODE`, Kismet `DEAUTHFLOOD` / `BCASTDISCON` / `DISCONCODEINVALID` / `DEAUTHCODEINVALID` → `POSSIBLE_DEAUTH_ATTACK` |
| Disassociation abuse | as above, for disassociation frames (counted together with deauth); traffic after disassociation (Kismet) | same signals, Kismet `DISASSOCTRAFFIC` |
| Repeated forced reconnect pattern | disconnected stations re-authenticate shortly after the burst, repeatedly | "disconnected stations re-authenticated" component of `POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT` |
| Suspicious EAPOL activity | per station or per BSSID EAPOL frame / handshake counts far above normal; EAPOL that *follows* a disconnect burst | `EAPOL_REAUTH_SURGE`, `POSSIBLE_HANDSHAKE_CAPTURE_ATTEMPT`, `BASELINE_DEVIATION` |
| Evil-twin indicators | an unregistered BSSID advertises a protected SSID, especially with weaker or incompatible security or on an unexpected channel | `UNKNOWN_BSSID_FOR_PROTECTED_SSID`, `INCOMPATIBLE_DUPLICATE_SSID`, `CHANNEL_ANOMALY`, Kismet `APSPOOF` → `POSSIBLE_EVIL_TWIN` |
| Security downgrade indicators | a BSSID advertises less than the registry expects or less than the registered AP: WPA3 → WPA2, PMF required → capable → none, changed ciphers / AKMs, a BSSID alternating between profiles | `SECURITY_DOWNGRADE`, `PMF_DOWNGRADE`, `ENCRYPTION_CHANGE`, Kismet `CRYPTODROP` / `ADVCRYPTCHANGE` |
| Weak configuration that enables offline attacks | transition mode, PMF optional or off, WPS advertised, legacy ciphers | `audit security` findings and recommendations |
| Loss of the sensor | adapter disappears from the system (USB reset, unplug) or the Kismet datasource fails | `SENSOR_LOST` / `SENSOR_RECOVERED` |

Daybreak reports *patterns*. A correlated alert says that the observed sequence
is consistent with, for example, an attempt to capture a WPA handshake. It does
not determine whether a handshake was captured, whether an attack succeeded or
who was responsible.

## Non-goals

- **Stopping offline cracking after handshake material has been obtained.** Once
  an attacker has recorded a 4-way handshake or a PMKID, the passphrase strength
  is the only defence; Daybreak can only point out that capture may have been
  attempted and recommend WPA3-SAE, PMF required and a strong passphrase.
- **Attacking suspected clients or access points.** No countermeasures, no
  containment deauths, no active probing: Daybreak never constructs or sends
  802.11 frames. `sensor prepare` and `sensor release` refuse to take down a
  sensor that is connected or associated (that would make the adapter send its
  own deauthentication), or one that serves a network (AP, ad-hoc, mesh); after
  `sensor release`, NetworkManager may use the adapter as a normal client again,
  including scans.
- **Identifying a human attacker.** MAC addresses in management frames are
  trivially forged; Daybreak records what was claimed, not who sent it.
- **Detecting RF jamming with high confidence.** Jamming is not decoded as frames;
  at best it shows up indirectly (sensor hears nothing, clients drop).
- **Active countermeasures or automatic remediation.** Daybreak never changes AP
  settings, the internet interface or system configuration.
- **Monitoring networks the operator is not authorized to monitor.** By default
  only registered networks are analysed and stored (`detection.scope: protected`).

## Trust boundaries

```text
  radio (untrusted)
      |  any nearby device can transmit any frame
      v
  [1] sensor adapter + kernel driver (mt7921u) ---- trusted to deliver frames,
      |                                              not to judge them
      v
  [2] Kismet (optional, local service) ------------ trusted for alerts and AP
      |  REST / eventbus, readonly API key             records; its own logs are
      |                                                outside Daybreak's control
      v
  [3] Daybreak process ----------------------------- parses untrusted frames,
      |  (root for the passive backend / frame tap)    guards interface changes
      v
  [4] local SQLite database and logs -------------- personal data at rest
      |
      v
  [5] dashboard (127.0.0.1, read-only) ------------ reachable by local users and
                                                     by web pages via the browser
```

1. **Sensor.** Everything received over the air is attacker-controlled: frame
   types, addresses, SSIDs (arbitrary bytes, terminal escapes, markup), element
   lengths, radiotap headers. Parsers bound every length, reject malformed frames
   without stopping the monitor, and drop bad-FCS frames. The sensor adapter is
   dedicated: it is never the interface that provides the operator's internet
   connection.
2. **Kismet.** A local service Daybreak trusts for its WIDS alerts, AP records and
   datasource state. Daybreak uses a *readonly* API key from an environment
   variable, calls only read endpoints with a field allow-list, and filters the
   responses again. Kismet's own logs can contain full frames, including
   handshakes; `daybreak-wids kismet config` suggests `enable_logging=false`.
3. **Daybreak process.** It runs as root with the passive backend (monitor mode
   and packet capture) and with the Kismet backend's frame tap (a packet socket
   that is only read, `CAP_NET_RAW`; on by default); only Kismet-only mode, which
   has no handshake-capture correlation, runs unprivileged. It changes interfaces
   only through the guarded sensor controller: protected interfaces, the
   default-route interface and interfaces on the same PHY are refused before
   every command, the target must still be the sensor adapter (ifindex / MAC),
   and protected interfaces are pinned at start and compared before and after
   each operation and every 10 s while monitoring. The command runner allows only
   the allow-listed `iw` / `ip` / `nmcli` commands at runtime, without a shell,
   from system directories, with a minimal environment (`tests/test_safety.py`
   checks literal forms over the source as a review tripwire); the desktop
   notifier's `notify-send` is the only other subprocess. Files it creates are
   owner-only and, under `sudo`, handed back to the invoking user.
4. **Database and logs.** Contain MAC addresses of APs and stations, SSIDs, signal
   levels, reason codes and alerts, but no frame payloads, key material or
   passphrases (metadata allow-list). Anyone who can read these files learns
   which devices used the network and when.
5. **Dashboard.** Read-only HTTP on loopback (GET only). Other local users can
   query it, and can tie up its connections; web pages in the operator's browser
   can try DNS rebinding, which the Host header allow-list blocks (literal names
   only, no wildcards). It has no authentication, so exposing it beyond loopback
   (`dashboard.allow_remote`) is an explicit operator decision.

## Threats to Daybreak itself

| Threat | Mitigation |
|---|---|
| Crafted frames crash or stall the parser | bounded parsing, per-frame error handling, malformed counters; an event whose processing still fails is counted and the monitor continues; fuzzed during the pre-release review with mutated synthetic frames, capture files, JSONL lines and Kismet records (scratch harness, not published; see VALIDATION.md): nothing but the documented format errors escaped |
| Crafted capture files or replay lines (offline analysis) | strict, bounded pcap/pcapng parsing; a corrupt capture ends the run and the frames before the bad block are analysed; implausible timestamps rejected; malformed or undecodable JSONL lines counted and skipped; a single far-off timestamp cannot hold a detection window open; date formatting never fails on stored data |
| SSID-based injection into the terminal, logs or dashboard | dashboard renders text nodes only (no `innerHTML`); console, human log and CLI output escape control characters, Unicode line separators, bidi and other invisible format characters; Kismet alert headers must be identifiers; desktop notifications are sent as plain text; JSONL is JSON-escaped |
| Flooding with random BSSIDs / stations to exhaust memory, CPU or disk | AP and station trackers and per-BSSID / per-station detector state are size-capped LRU structures (registered BSSIDs are never evicted), incident and alert bookkeeping are capped, and expiry also runs every 10,000 events (frozen timestamps); event rows are sampled per (event type, BSSID) and overall, and new rows for unregistered APs and for new stations are budgeted per hour (detection still sees every event). Frames that name a registered BSSID stay in scope with `scope: protected` even when their other addresses are random, so such a flood still costs CPU |
| Alert flooding to hide a real alert | per-type cooldown with escalation; notification budgets per severity band (LOW floods cannot use up the budget of HIGH alerts); new alerts about BSSIDs outside the protected networks are limited per type (6 per minute, counted as `flood_suppressed`), alerts about protected networks never; suppressed and skipped counts are reported. Alerts skipped by a notification rate limit are still stored and written to JSONL, but a repeat of an alert type for the same network within `alerts.cooldown` (300 s) is only counted on the earlier alert (`suppressed_count`), so a decoy can hide the details (e.g. the BSSID) of a second alert for up to 5 minutes; `audit security` and the AP table still list it |
| Look-alike SSIDs (trailing NUL, zero-width characters) | not detected: treated as a different network (see README limitations) |
| Evasion below thresholds (slow, targeted deauth) | baseline deviation helps on networks with a learned baseline; slow single-client attacks may stay below thresholds (see limitations) |
| Evasion by attacking on another channel than the sensor listens to | single radio: hopping can miss bursts; dedicate the sensor to the protected channel |
| Tampering with the configuration to point the sensor at the internet interface | the guard refuses the configured protected interfaces, the default-route interface and same-PHY interfaces; `sensor.protected_interfaces` must not be empty; `sensor prepare --apply` refuses while a configured protected interface does not exist (typo); prepare and release refuse an adapter whose driver / MAC is not the configured sensor's and one that is connected, associated or serving a network. An internet interface that is neither listed as protected nor carrying the default route is protected only by those identity and in-use checks |
| USB re-enumeration hands the sensor's old name to another adapter | commands and channel hops check the adapter's MAC; recovery only re-prepares the configured sensor (name, or expected MAC and driver) |
| Secret leakage (Kismet API key) | read from the environment and sent only as a request header; the Kismet URL may not carry credentials; neither the REST client nor the eventbus connection follows redirects or uses a proxy from the environment; a warning when credentials would go over plain http to another host; `api_key_env` must be a variable name, not the key; never written to the database, logs or dashboard responses |
| Neighbouring networks attributed to a protected one (scope bypass) | Kismet alerts are attributed only by registered BSSID or the whole quoted protected SSID, never by substring |
| Key material smuggled through replayed or relayed metadata | strict top-level key allow-list, scalar values only |

## False positives

Disconnects, reconnects and new BSSIDs are part of normal Wi-Fi operation.
These situations can produce alerts without any attack:

| Situation | What it can look like | How Daybreak limits it |
|---|---|---|
| Client roaming between APs or bands | disassociation (reason 8) followed by reassociation and a new handshake | single disconnects never alert; roaming between *registered* BSSIDs is normal (`normal.jsonl` covers this) |
| AP reboot or firmware update | one broadcast deauth, then every client reconnects and re-authenticates at once (EAPOL surge) | a single broadcast frame does not reach the broadcast threshold; the EAPOL surge alone is INFO; a learned baseline helps |
| Signal loss / client walking out of range | disconnects and reconnects, retransmissions | retransmissions are de-duplicated; one station rarely reaches burst thresholds |
| Client power saving / idle timeouts | AP disassociates idle stations (reason 4) | individual frames only; no burst |
| Band steering, client steering, load balancing | AP deauths or disassociates several clients in a short time | can raise `MULTI_CLIENT_DEAUTH` (INFO, 15 points); correlated alerts still need a burst or broadcast disconnects |
| DFS radar event / channel change | AP moves channel, clients follow; possible `CHANNEL_ANOMALY` | register every channel the AP may use |
| Mesh systems, extenders, guest networks | additional BSSIDs advertising the protected SSID | `UNKNOWN_BSSID_FOR_PROTECTED_SSID` is LOW and includes a hint to register the BSSID; the evil-twin alert needs weaker security from that BSSID as well |
| Neighbours using the same default SSID (ISP routers) | an unregistered BSSID with the protected SSID | same as above; consider a less generic SSID |
| WPA3 transition mode | clients choosing WPA2-PSK on a WPA2/WPA3 network | per-client choice is not alerted; audit reports transition mode as INFO |
| Group key rekeying | periodic EAPOL group-key frames | handshakes are counted from message 1 only; a rekey adds 2 EAPOL frames per station, far below the per-station frame threshold (12 in 60 s) |
| Sensor placement | RSSI of frames from the real AP varies with position | `SUSPICIOUS_SOURCE` needs several frames and a large deviation (default 20 dB or 4 sigma) |

Default thresholds are starting points, not values tuned on real attack data.
Learn a baseline (`daybreak-wids baseline create`) during a quiet period and
adjust `detection.*` and `scoring.weights` to the network.
