#!/usr/bin/env bash
# Kernel packet cap experiment (internal/kcap).
#
# Creates its own docker network with two containers: a sink with 30 known
# open TCP ports and a scanner (the product runtime: user 10001, cap_drop ALL,
# NET_RAW and NET_ADMIN). nmap SYN-scans the sink's port range at a pinned
# rate. Nothing outside this network is ever scanned.
#
# Phases:
#   before   cap off, nmap frozen (SIGSTOP) for FREEZE seconds, then SIGCONT
#   after    cap on (czujka kcap apply), the same freeze
#   normal   cap on, no freeze: dropped must stay 0
#   nocap    cap off, no freeze: the ports found must equal those of "normal"
# For each phase: SYN packets per second from tcpdump on the scanner's
# interface (outgoing only; the kernel drops a packet before tcpdump sees it).
#
#   e2e/kcap/run.sh                 # all phases
#   KCAP_PHASES="before after" e2e/kcap/run.sh
#
# Settings: KCAP_PPS (500), KCAP_FREEZE (15 s), KCAP_PORTS (1-20000),
# KCAP_SUBNET (192.168.231.0/24), CZUJKA_BIN (a linux czujka binary; default:
# go build for the docker server's architecture), KCAP_KEEP=1 keeps the image.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
P=${KCAP_PREFIX:-kcap}
NET=$P-net
SUBNET=${KCAP_SUBNET:-192.168.231.0/24}
base=${SUBNET%.*}
SINK_IP=$base.10
SCAN_IP=$base.20
PPS=${KCAP_PPS:-500}
FREEZE=${KCAP_FREEZE:-15}
PORTS=${KCAP_PORTS:-1-20000}
PHASES=${KCAP_PHASES:-before after normal nocap}
OPEN="21 22 25 53 80 110 143 443 445 993 995 1433 1521 2049 3000 3306 3389 5000 5432 5672 5900 6379 8000 8080 8081 8443 9000 9200 11211 15672"
RATE=$(( (PPS * 11 + 9) / 10 ))
BURST=$(( (RATE + 9) / 10 ))
S=$P-scanner

cleanup() {
  docker rm -f "$P-sink" "$S" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  if [ -z "${KCAP_KEEP:-}" ]; then docker rmi -f "$P-scanner:dev" >/dev/null 2>&1 || true; fi
  if [ -n "${ctx:-}" ]; then rm -rf "$ctx"; fi
}
trap cleanup EXIT

echo "# kcap experiment $(date -u +%FT%TZ) on $(uname -n): docker $(docker version -f '{{.Server.Version}}'), kernel $(docker info -f '{{.KernelVersion}}')"
echo "# cap $PPS pps -> kernel limit $RATE/s burst $BURST; freeze $FREEZE s; ports $PORTS; sink $SINK_IP"

ctx=$(mktemp -d)
if [ -n "${CZUJKA_BIN:-}" ]; then
  cp "$CZUJKA_BIN" "$ctx/czujka"
else
  case $(docker info -f '{{.Architecture}}') in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "unknown docker architecture" >&2; exit 1 ;;
  esac
  (cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$ctx/czujka" ./cmd/czujka)
fi
cp "$here/Dockerfile.scanner" "$ctx/Dockerfile"
docker build -q -t "$P-scanner:dev" "$ctx" >/dev/null

docker network create --subnet "$SUBNET" "$NET" >/dev/null
docker run -d --name "$P-sink" --network "$NET" --ip "$SINK_IP" alpine:3.22 sh -c \
  "for p in $OPEN; do (while true; do nc -l -p \$p >/dev/null 2>&1 </dev/null; done) & done; wait" >/dev/null
docker run -d --name "$S" --network "$NET" --ip "$SCAN_IP" \
  --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN --read-only --tmpfs /tmp "$P-scanner:dev" >/dev/null
sleep 2

# per_second FILE: SYN count per second of a tcpdump -tt log; prints the table and the maximum.
per_second() {
  awk '/^[0-9]+\./ { split($1, t, "."); n[t[1]]++ } END { for (s in n) print s, n[s] }' "$1" | sort -n |
    awk 'NR == 1 { t0 = $1 } { printf "  t+%03ds %6d\n", $1 - t0, $2; if ($2 > max) max = $2 } END { printf "  max %d pps\n", max }'
}

run_phase() {
  local phase=$1 cap=$2 freeze=$3
  echo
  echo "## phase $phase: cap $cap, freeze $freeze s"
  if [ "$cap" = on ]; then
    docker exec "$S" czujka kcap apply --pps "$PPS"
  else
    docker exec "$S" czujka kcap remove 2>/dev/null || true
  fi
  docker exec -u 0 -d "$S" sh -c "exec tcpdump -i eth0 -Q out -nn -tt -l 'tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' >/tmp/syn-$phase.txt 2>/tmp/tcpdump-$phase.err"
  sleep 2
  docker exec -d "$S" sh -c "exec nmap -sS -Pn -p $PORTS -n -T4 -v --min-rate $PPS --max-rate $PPS --max-retries 2 --privileged -oG /tmp/nmap-$phase.gnmap $SINK_IP >/tmp/nmap-$phase.out 2>&1"
  if [ "$freeze" -gt 0 ]; then
    sleep 10
    docker exec "$S" pkill -STOP -x nmap
    echo "  $(date -u +%T) SIGSTOP nmap"
    sleep "$freeze"
    docker exec "$S" pkill -CONT -x nmap
    echo "  $(date -u +%T) SIGCONT nmap"
  fi
  while docker exec "$S" pgrep -x nmap >/dev/null; do sleep 1; done
  sleep 1
  docker exec -u 0 "$S" pkill -x tcpdump || true
  sleep 1
  docker exec "$S" cat "/tmp/syn-$phase.txt" >"$ctx/syn-$phase.txt"
  echo "  SYN packets per second on the scanner's interface:"
  per_second "$ctx/syn-$phase.txt"
  echo "  SYN packets total: $(grep -c '^[0-9]' "$ctx/syn-$phase.txt" || true)"
  if [ "$cap" = on ]; then
    echo "  kernel counter: $(docker exec "$S" czujka kcap status)"
  fi
  local found
  found=$(docker exec "$S" cat "/tmp/nmap-$phase.gnmap" | tr ',' '\n' | grep -o '[0-9]*/open' | cut -d/ -f1 | sort -n | tr '\n' ' ')
  echo "  open ports found ($(echo $found | wc -w | tr -d ' ')): $found"
  printf -v "found_$phase" '%s' "$found"
  docker exec "$S" grep -E 'Raw packets sent|Nmap done' "/tmp/nmap-$phase.out" | sed 's/^/  nmap: /'
}

for ph in $PHASES; do
  case $ph in
    before) run_phase before off "$FREEZE" ;;
    after) run_phase after on "$FREEZE" ;;
    normal) run_phase normal on 0 ;;
    nocap) run_phase nocap off 0 ;;
    *) echo "unknown phase $ph" >&2; exit 2 ;;
  esac
done

want=$(echo $OPEN | tr ' ' '\n' | sort -n | tr '\n' ' ')
echo
echo "## ports"
echo "  expected: $want"
for ph in $PHASES; do
  v="found_$ph"
  if [ "${!v}" = "$want" ]; then echo "  $ph: all 30 found"; else echo "  $ph: DIFFERENT: ${!v}"; fi
done
