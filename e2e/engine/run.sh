#!/usr/bin/env bash
# End-to-end check of the scan engine against a real docker network.
#
#   ./e2e/engine/run.sh          run every scenario, then remove the lab
#   KEEP=1 ./e2e/engine/run.sh   leave the lab running
#
# It creates the lab (lab.sh): network 10.77.0.0/22 with seven hosts, a
# router to a second network, and an empty /20 for the chunk-size test. It builds scanprobe for linux and runs it in a
# container that has nmap. Nothing outside these docker networks is scanned.
#
# Two scanner positions:
#   l2      the scanner sits in the lab network (10.77.0.2): nmap uses ARP
#   routed  the scanner sits in 10.78.0.0/24 and reaches the lab through
#           the router, like a campus network: ICMP and TCP probes only
set -uo pipefail
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
IMG=czeng-lab:latest
OUT="$PWD/out"
BIN="$PWD/.bin"
PORTS="top-100,6379,8765,9443"
EXCL="10.77.0.1,10.77.0.2,10.77.3.254" # docker gateway, the scanner (l2), the router
FAILED=0

cleanup() { if [ -z "${KEEP:-}" ]; then ./lab.sh down; fi; }
trap cleanup EXIT

mkdir -p "$OUT" "$BIN"
ARCH=$(docker version --format '{{.Server.Arch}}')
echo "== build scanprobe for linux/$ARCH"
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$BIN/scanprobe" ./cmd/scanprobe) || exit 1
(cd "$ROOT" && go build -o "$BIN/verify" ./e2e/engine/verify) || exit 1

echo "== start the lab"
./lab.sh up || exit 1

# scan NAME POSITION scanprobe-args...   POSITION: l2 | routed | noraw
scan() {
  local name=$1 pos=$2; shift 2
  echo
  echo "== $name ($pos): scanprobe $*"
  case "$pos" in
    l2)
      docker run --rm --name czeng-scanner --network czeng-net --ip 10.77.0.2 -v "$BIN:/work:ro" \
        --entrypoint /work/scanprobe "$IMG" "$@" >"$OUT/$name.jsonl" 2>"$OUT/$name.log" ;;
    noraw) # no raw sockets: nmap has to fall back to the connect scan
      docker run --rm --name czeng-scanner --network czeng-net --ip 10.77.0.2 -v "$BIN:/work:ro" \
        --cap-drop NET_RAW --cap-drop NET_ADMIN --entrypoint /work/scanprobe "$IMG" "$@" >"$OUT/$name.jsonl" 2>"$OUT/$name.log" ;;
    routed)
      docker run --rm --name czeng-scanner --network czeng-scan --ip 10.78.0.2 --cap-add NET_ADMIN -v "$BIN:/work:ro" \
        --entrypoint sh "$IMG" -c 'ip route add 10.77.0.0/22 via 10.78.0.254 && ip route add 10.79.0.0/20 via 10.78.0.254 && exec /work/scanprobe "$@"' sh "$@" >"$OUT/$name.jsonl" 2>"$OUT/$name.log" ;;
  esac
  echo "exit code $?"
  grep -E 'probe engine|estimate:|scan plan ready|window guard|PAUSED|unstable host|run refused|COMPLETED|FAILED' "$OUT/$name.log" | sed -E 's/^time=[^ ]+ level=//' | cut -c1-420
}
check() { "$BIN/verify" -in "$OUT/$1.jsonl" "${@:2}" || FAILED=1; }

# A. Full sweep on the local segment: ARP discovery, SYN scan, version detection.
scan A-local l2 -targets 10.77.0.0/22 -exclude "$EXCL" -ports "$PORTS" -pps 500 -measure-iface eth0 -quiet
check A-local -expect lab

# B. Full sweep through the router: ICMP echo, ICMP timestamp, TCP SYN and
#    TCP ACK probes. 10.77.3.60 drops ICMP and must be found by a TCP probe.
scan B-routed routed -targets 10.77.0.0/22 -exclude "$EXCL" -ports "$PORTS" -pps 500 -measure-iface eth0 -quiet
check B-routed -expect lab
echo "discovery reason of the host that drops ICMP: $(grep '"ip":"10.77.3.60"' "$OUT/B-routed.jsonl" | sed -E 's/.*"reason":"([^"]+)".*/\1/')"

# C. Discovery and port scan only, through the router: the sweep speed.
scan C-sweep routed -targets 10.77.0.0/22 -exclude "$EXCL" -ports "$PORTS" -pps 500 -no-sv -measure-iface eth0 -quiet
check C-sweep -expect lab-ports

# D1. The window closes after 45 s. Two chunks finish; the guard sees that
#     the next chunk does not fit and starts nothing more. The run pauses,
#     then resumes and finishes the deferred chunks.
scan D1-window-guard routed -targets 10.77.0.0/22 -exclude "$EXCL" -ports "$PORTS" -pps 500 -stop-after 45s -resume -measure-iface eth0 -quiet
grep -E '"event":"paused"' "$OUT/D1-window-guard.log" | cut -c1-420
check D1-window-guard -expect lab -sessions 2

# D2. The window closes after 22 s, in the middle of the first chunks: the
#     running nmap processes are stopped at the deadline, every chunk is
#     deferred, and the resumed run does them all.
scan D2-window-cut routed -targets 10.77.0.0/22 -exclude "$EXCL" -ports "$PORTS" -pps 500 -stop-after 22s -resume -measure-iface eth0 -quiet
grep -E '"event":"paused"' "$OUT/D2-window-cut.log" | cut -c1-420
check D2-window-cut -expect lab -sessions 2

# E. Unstable hosts. 10.77.3.60 is off the network when the scan starts and
#    comes back after the first discovery round. 10.77.3.99 does not exist.
docker network disconnect czeng-net czeng-noicmp
: >"$OUT/E-retry.log"
( for _ in $(seq 1 300); do grep -q 'nmap done.*stage=discover' "$OUT/E-retry.log" 2>/dev/null && break; sleep 0.2; done
  docker network connect --ip 10.77.3.60 czeng-net czeng-noicmp; echo "(10.77.3.60 is back on the network)" ) &
scan E-retry routed -targets 10.77.3.48/28,10.77.3.96/28 -ports "$PORTS" -pps 500 \
  -hints 10.77.3.60:80,10.77.3.99:80 -retries 2 -backoff 6s -quiet -v
wait
check E-retry -expect none
grep -E '"ip":"10.77.3.(60|99)"' "$OUT/E-retry.jsonl" | sed -E 's/.*"ip":"([^"]+)".*"up":(true|false),"reason":"([^"]+)".*"attempts":([0-9]+).*/retry result: \1 up=\2 reason=\3 attempts=\4/'
grep -q '"ip":"10.77.3.60".*"up":true.*"attempts":[23]' "$OUT/E-retry.jsonl" || { echo "FAIL: 10.77.3.60 should be found on a retry round"; FAILED=1; }
grep -q '"ip":"10.77.3.99".*"up":false.*"attempts":3' "$OUT/E-retry.jsonl" || { echo "FAIL: 10.77.3.99 should be reported down after 3 attempts"; FAILED=1; }

# F. Native Go fallback (as if nmap was not installed): TCP connect only.
scan F-native l2 -targets 10.77.0.0/22 -exclude "$EXCL" -ports "$PORTS" -pps 500 -native -measure-iface eth0 -quiet
check F-native -expect lab-ports

# G. No raw sockets: nmap switches to the connect scan (-sT) by itself.
scan G-unprivileged noraw -targets 10.77.0.0/23 -exclude "$EXCL" -ports "$PORTS" -pps 500 -measure-iface eth0 -quiet
check G-unprivileged -expect none

# I. Adaptive chunk groups on a larger scope: 4094 addresses of empty space
#    at 2000 pps. The groups start at 256 addresses and grow with the speed.
scan I-adaptive routed -targets 10.79.0.0/20 -exclude 10.79.0.1,10.79.15.254 -ports "$PORTS" -pps 2000 -measure-iface eth0 -quiet
check I-adaptive -expect none

# H. Emergency stop: the engine refuses to start and sends nothing.
scan H-emergency l2 -targets 10.77.0.0/22 -ports "$PORTS" -emergency-stop -measure-iface eth0 -quiet
check H-emergency -expect none -status failed

echo
if [ "$FAILED" = 0 ]; then echo "E2E RESULT: PASS"; else echo "E2E RESULT: FAIL"; fi
exit "$FAILED"
