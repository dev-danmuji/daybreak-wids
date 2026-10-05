#!/usr/bin/env bash
# daybreak-wids: passive real-hardware smoke test (run by the operator).
#
# Authorized defensive monitoring only: run this on a network you own or
# administer. Nothing here transmits. The only state that changes is the
# *sensor* adapter (monitor mode, channel), through daybreak-wids' guarded
# `sensor prepare/release` commands, which refuse protected interfaces, the
# default-route interface and any interface on the same PHY.
#
# Usage, from the repository root, as your normal user (sudo is asked for):
#
#   scripts/hardware-smoke-test.sh discover   # list BSSIDs heard for your SSID (nothing adopted)
#   scripts/hardware-smoke-test.sh run        # the smoke test (default)
#
# Environment: CONFIG (config.yaml), CHANNEL (149), DURATION (300 s),
#              DISCOVER_SECONDS (60), PROTECTED (wlo1), DAYBREAK (daybreak-wids on PATH)
#
# `run` needs a *configured* protected network (SSID + BSSID) on $CHANNEL in
# $CONFIG; `discover` needs at least the SSID (`daybreak-wids network add
# --name home --ssid '<your SSID>' --channel 149`).
#
# During the `run` window, disconnect and reconnect one of YOUR OWN devices
# (phone Wi-Fi off, then on). Optionally unplug the sensor adapter for ~10 s and
# plug it back in to exercise SENSOR_LOST / SENSOR_RECOVERED.
#
# Raw records go to var/validation/<timestamp>/ (git-ignored: they contain your
# SSIDs and MAC addresses; do not publish them). summary.txt holds counts only.

set -euo pipefail
umask 077   # the raw records contain your SSIDs and MAC addresses

MODE=${1:-run}
CONFIG=${CONFIG:-config.yaml}
CHANNEL=${CHANNEL:-149}
DURATION=${DURATION:-300}
DISCOVER_SECONDS=${DISCOVER_SECONDS:-60}
PROTECTED=${PROTECTED:-wlo1}
DAYBREAK=${DAYBREAK:-$(command -v daybreak-wids || true)}

die() { echo "error: $*" >&2; exit 2; }
say() { echo; echo "== $*"; }

case "$MODE" in run|discover) ;; *) die "usage: $0 [run|discover]" ;; esac
[ "$(id -u)" -ne 0 ] || die "run as your normal user; the script calls sudo only for daybreak-wids itself"
[ -n "$DAYBREAK" ] && [ -x "$DAYBREAK" ] || die "daybreak-wids not found (activate the venv or set DAYBREAK=/path/to/daybreak-wids)"
DAYBREAK=$(readlink -f "$DAYBREAK")
[ -f "$CONFIG" ] || die "config file $CONFIG not found (cp config.example.yaml config.yaml and register your network)"
CONFIG=$(readlink -f "$CONFIG")
for tool in python3 nmcli iw ip sudo; do command -v "$tool" >/dev/null || die "$tool is required"; done
[[ "$CHANNEL" =~ ^[0-9]+$ ]] || die "CHANNEL must be a number"
[[ "$DURATION" =~ ^[0-9]+$ && "$DISCOVER_SECONDS" =~ ^[0-9]+$ ]] || die "DURATION/DISCOVER_SECONDS must be whole seconds"

db() { "$DAYBREAK" -c "$CONFIG" "$@"; }
sdb() { sudo "$DAYBREAK" -c "$CONFIG" "$@"; }

OUT=var/validation/$(date +%Y%m%d-%H%M%S)-$MODE
mkdir -p "$OUT"
echo "records: $OUT (local only)"

# --- read-only state of the protected interface ---------------------------------
protected_state() {
  printf 'nm=%s\n' "$(nmcli -t -f DEVICE,STATE device status | awk -F: -v d="$PROTECTED" '$1==d{print $2}')"
  printf 'operstate=%s\n' "$(cat "/sys/class/net/$PROTECTED/operstate" 2>/dev/null || echo missing)"
  printf 'iwtype=%s\n' "$(iw dev "$PROTECTED" info 2>/dev/null | awk '$1=="type"{print $2}')"
  printf 'link=%s\n' "$(ip -o link show dev "$PROTECTED" 2>/dev/null | sed -E 's/^[0-9]+: //; s/ qlen [0-9]+//')"
  printf 'default_route_dev=%s\n' "$(ip route show default | awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}' | sort -u | paste -sd,)"
}

check_invariant() {  # $1 = label
  protected_state > "$OUT/protected-$1.txt"
  if ! diff -u "$OUT/protected-before.txt" "$OUT/protected-$1.txt" > "$OUT/protected-$1.diff"; then
    echo "INVARIANT VIOLATED after '$1': $PROTECTED changed:" >&2
    cat "$OUT/protected-$1.diff" >&2
    return 1
  fi
  echo "invariant ok after '$1': $PROTECTED unchanged ($(grep '^nm=' "$OUT/protected-$1.txt"))"
}

SENSOR=""
PREPARED=0
MON_PID=""
WATCH_PID=""

stop_monitor() {  # the monitor runs as root: signal it through sudo (sudo relays it)
  [ -n "$MON_PID" ] || return 0
  if ps -p "$MON_PID" > /dev/null 2>&1; then
    sudo -n kill -INT "$MON_PID" 2>/dev/null || sudo kill -INT "$MON_PID" 2>/dev/null || true
    wait "$MON_PID" 2>/dev/null || true
  fi
  MON_PID=""
}

release_sensor() {
  [ "$PREPARED" -eq 1 ] || return 0
  PREPARED=0
  say "release: returning $SENSOR to managed mode"
  sdb sensor release --apply 2>&1 | tee "$OUT/release.txt" || echo "release failed; run: sudo $DAYBREAK -c $CONFIG sensor release --apply" >&2
}

cleanup() {
  local rc=$?
  [ -n "$WATCH_PID" ] && kill "$WATCH_PID" 2>/dev/null || true
  stop_monitor
  release_sensor
  # Files written by the root-run monitor: hand them back to you (symlinks are not followed).
  if [ -d var ]; then sudo chown -R -h "$(id -u):$(id -g)" var 2>/dev/null || true; fi
  if [ -s "$OUT/protected-before.txt" ]; then check_invariant final || rc=3; fi
  { echo; echo '$ nmcli device status'; nmcli device status; } >> "$OUT/final-state.txt" 2>&1 || true
  echo; echo "records in $OUT"; exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# --- 1. pre-flight (read-only) --------------------------------------------------
say "pre-flight (read-only)"
{ date -Is; uname -r; echo; echo '$ nmcli device status'; nmcli device status; echo; echo '$ iw dev'; iw dev
  echo; echo '$ iw reg get'; iw reg get; echo; echo '$ ip route show default'; ip route show default; } > "$OUT/preflight.txt" 2>&1
protected_state > "$OUT/protected-before.txt"
cat "$OUT/protected-before.txt" | sed -E 's/link=.*/link=(recorded)/'
grep -q '^nm=connected$' "$OUT/protected-before.txt" || die "$PROTECTED is not connected; the test expects the internet link to be up"
db --json sensor list > "$OUT/sensor-list.json"
read -r SENSOR ROLE_OK < <(python3 - "$OUT/sensor-list.json" "$PROTECTED" <<'EOF'
import json, sys
rows = json.load(open(sys.argv[1]))
sensor = next((r["interface"] for r in rows if r.get("role") == "sensor"), "")
prot = next((r for r in rows if r["interface"] == sys.argv[2]), None)
print(sensor or "-", "yes" if prot and str(prot.get("role", "")).startswith("protected") else "no")
EOF
)
[ "$SENSOR" != "-" ] || die "configured sensor adapter not found (see: daybreak-wids sensor list)"
[ "$SENSOR" != "$PROTECTED" ] || die "sensor and protected interface are the same"
[ "$ROLE_OK" = yes ] || die "$PROTECTED is not listed as protected in $CONFIG (sensor.protected_interfaces)"
echo "sensor: $SENSOR   protected: $PROTECTED   regdomain: $(iw reg get | awk '/^country/{print $2; exit}' | tr -d :)"
db sensor check > "$OUT/sensor-check.txt" 2>&1 || true

db --json network list > "$OUT/networks.json"
read -r CONFIGURED SSID_ONLY < <(python3 - "$OUT/networks.json" "$CHANNEL" <<'EOF'
import json, sys
nets, ch = json.load(open(sys.argv[1])), int(sys.argv[2])
on_ch = [n for n in nets if not n["channels"] or ch in n["channels"]]
print(sum(n["status"] == "configured" for n in on_ch), sum(n["status"] != "configured" for n in on_ch))
EOF
)
if [ "$MODE" = run ] && [ "$CONFIGURED" -eq 0 ]; then
  die "no configured network on channel $CHANNEL in $CONFIG; register SSID + BSSID first (or run '$0 discover')"
fi
if [ "$MODE" = discover ] && [ "$((CONFIGURED + SSID_ONLY))" -eq 0 ]; then
  die "register your SSID first: $DAYBREAK -c $CONFIG network add --name home --ssid '<your SSID>' --channel $CHANNEL"
fi

# --- 2. prepare the sensor only -------------------------------------------------
say "prepare: $SENSOR -> monitor mode, channel $CHANNEL, via sudo"
db sensor prepare --channel "$CHANNEL" > "$OUT/prepare-plan.txt"
cat "$OUT/prepare-plan.txt"
PREPARED=1
sdb sensor prepare --apply --channel "$CHANNEL" 2>&1 | tee "$OUT/prepare.txt"
check_invariant after-prepare || exit 3
iw dev "$SENSOR" info > "$OUT/sensor-after-prepare.txt" 2>&1 || true
grep -q 'type monitor' "$OUT/sensor-after-prepare.txt" || die "$SENSOR is not in monitor mode after prepare"
echo "sensor: $(awk '$1=="type"||$1=="channel"{printf "%s ", $0}' "$OUT/sensor-after-prepare.txt")"

# --- 3. passive monitoring --------------------------------------------------------
SECONDS_TO_RUN=$DURATION
[ "$MODE" = discover ] && SECONDS_TO_RUN=$DISCOVER_SECONDS
say "monitor: passive backend for ${SECONDS_TO_RUN}s (Ctrl-C stops early)"
if [ "$MODE" = run ]; then
  echo "   now: turn Wi-Fi OFF on one of your own devices, wait ~10 s, turn it back ON."
  echo "   optional: unplug the sensor adapter for ~10 s, then plug it back in."
fi
echo "   live output: tail -f $OUT/monitor.txt"
START=$(date +%s)
sdb monitor start --backend passive --duration "$SECONDS_TO_RUN" > "$OUT/monitor.txt" 2>&1 &
MON_PID=$!
( while sleep 5; do
    sudo -n -v 2>/dev/null || true   # keep the sudo timestamp alive so the watcher can always stop the monitor
    if ! check_invariant during-monitor > /dev/null 2>&1; then
      echo "INVARIANT VIOLATED during monitoring; stopping" >&2
      sudo -n kill -INT "$MON_PID" 2>/dev/null || true
      break
    fi
  done ) &
WATCH_PID=$!
MON_RC=0
wait "$MON_PID" || MON_RC=$?
MON_PID=""
kill "$WATCH_PID" 2>/dev/null || true
WATCH_PID=""
END=$(date +%s)
tail -n 3 "$OUT/monitor.txt"
check_invariant after-monitor || exit 3

# --- 4. results ---------------------------------------------------------------------
SINCE="$(( END - START + 120 ))s"
sdb --json report --since "$SINCE" > "$OUT/report.json" 2>/dev/null || echo '{}' > "$OUT/report.json"
if [ "$MODE" = discover ]; then
  say "candidates heard for your SSID (not adopted; verify they are yours before registering)"
  sdb network list
  sdb audit security || true
  echo
  echo "register with: $DAYBREAK -c $CONFIG network add --replace --name <name> --ssid '<SSID>' --bssid <BSSID> --channel $CHANNEL ..."
  exit 0
fi

LOGDIR=$(python3 - "$CONFIG" <<'EOF'
import os, sys, yaml
cfg = yaml.safe_load(open(sys.argv[1])) or {}
d = (cfg.get("logging") or {}).get("directory", "var/log")
print(d if os.path.isabs(d) else os.path.join(os.path.dirname(sys.argv[1]), d))
EOF
) || LOGDIR=var/log
python3 - "$OUT/report.json" "$OUT/monitor.txt" "$LOGDIR" "$MON_RC" "$SENSOR" "$CHANNEL" "$(( END - START ))" \
    > "$OUT/summary.txt" <<'EOF'
import json, os, sys
rep_path, mon_path, logdir, rc, sensor, channel, seconds = sys.argv[1:8]
rep = json.load(open(rep_path))
mon = open(mon_path, errors="replace").read()
ev = rep.get("events") or {}
al = rep.get("alerts") or {}
by_sev = al.get("by_severity") or {}
statuses = [s.get("status") for s in (rep.get("sensor") or {}).get("status") or []]
def lines(name):
    p = os.path.join(logdir, name)
    try:
        return sum(1 for _ in open(p, errors="replace"))
    except OSError:
        return "missing"
proc = next((l for l in mon.splitlines() if l.startswith("processed ")), "processed: (not reported)")
print(f"sensor interface      : {sensor}")
print(f"channel               : {channel}")
print(f"monitor seconds       : {seconds} (exit code {rc})")
print(f"monitor summary       : {proc}")
print(f"protected unchanged   : {'protected interfaces unchanged' in mon}")
print("events stored by type : " + (", ".join(f"{k}={v}" for k, v in sorted(ev.items())) or "none"))
print("alerts by severity    : " + (", ".join(f"{k}={v}" for k, v in sorted(by_sev.items())) or "none"))
print("alerts by type        : " + (", ".join(f"{k}={v}" for k, v in sorted((al.get('by_type') or {}).items())) or "none"))
print(f"HIGH/CRITICAL alerts  : {sum(by_sev.get(k, 0) for k in ('HIGH', 'CRITICAL'))}")
print("sensor status records : " + (", ".join(s for s in statuses if s) or "none"))
print(f"alerts.jsonl lines    : {lines('alerts.jsonl')}")
print(f"daybreak.log lines    : {lines('daybreak.log')}")
EOF
say "summary (counts only, safe to share)"
cat "$OUT/summary.txt"
