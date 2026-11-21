#!/usr/bin/env bash
# Kernel packet cap in the product (internal/kcap through cmd/czujka, the
# runner and the API), on the real stack built from deploy/Dockerfile.
#
#  1. bridge mode with the scan-network overlay: the stack joins its own
#     network kcap-net with a sink of 30 open ports (nothing else is scanned);
#     kernel_cap in GET /settings/safety and /healthz (admin only); a policy
#     change replaces the rule; a normal run (dropped 0, 30 services) and a run
#     whose nmap is frozen for FREEZE s (the run note, dropped > 0).
#  2. host-network mode with CZUJKA_KERNEL_CAP=require: the cap is reported as
#     unavailable, no table is created in the host's namespace, a run is
#     refused with 409 kernel_cap.
#
#   e2e/kcap/product.sh            # needs docker compose, curl, jq; Linux for step 2
# Settings: KCAP_PORT (18089), KCAP_DB_PORT (55499, host-network step),
# KCAP_SUBNET (192.168.231.0/24), KCAP_FREEZE (15), KCAP_SKIP_HOST=1.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cd "$root"
PROJECT=kcapprod
NET=kcap-net
SUBNET=${KCAP_SUBNET:-192.168.231.0/24}
SINK_IP=${SUBNET%.*}.10
PORT=${KCAP_PORT:-18089}
FREEZE=${KCAP_FREEZE:-15}
OPEN="21 22 25 53 80 110 143 443 445 993 995 1433 1521 2049 3000 3306 3389 5000 5432 5672 5900 6379 8000 8080 8081 8443 9000 9200 11211 15672"
PW=kcap-$(head -c 9 /dev/urandom | od -An -tx1 | tr -d ' \n')
ADMIN=admin@czujka.local
tmp=$(mktemp -d)
JAR=$tmp/jar
# Own image names: the stack must not retag images of other stacks on this host.
cat >"$tmp/images.yml" <<'EOF'
services:
  db:
    image: czujka-db:kcap
  czujka:
    image: czujka:kcap
EOF
export CZUJKA_PORT=$PORT CZUJKA_ADMIN_PASSWORD=$PW CZUJKA_SCAN_NETWORK=$NET CZUJKA_DB_HOST_PORT=${KCAP_DB_PORT:-55499}
DC_BRIDGE=(docker compose -p $PROJECT -f deploy/docker-compose.yml -f deploy/docker-compose.scan-network.yml -f "$tmp/images.yml")
DC_HOST=(docker compose -p $PROJECT -f deploy/docker-compose.yml -f deploy/docker-compose.host-network.yml -f "$tmp/images.yml")
CZ=$PROJECT-czujka-1

cleanup() {
  "${DC_BRIDGE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  docker rm -f kcap-sink kcap-tcpdump >/dev/null 2>&1 || true
  docker network rm $NET >/dev/null 2>&1 || true
  if [ -z "${KCAP_KEEP:-}" ]; then docker rmi -f czujka:kcap czujka-db:kcap kcap-tcpdump:dev >/dev/null 2>&1 || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT

API=http://127.0.0.1:$PORT/api/v1
login() {
  CSRF=$(curl -sS -c "$JAR" -H 'Content-Type: application/json' -d "{\"email\":\"$ADMIN\",\"password\":\"$PW\"}" $API/auth/login | jq -r .csrf_token)
}
api() { # METHOD PATH [JSON]
  curl -sS -b "$JAR" -H "X-CSRF-Token: ${CSRF:-}" -H 'Content-Type: application/json' -X "$1" ${3:+-d "$3"} "$API$2"
}
wait_run() {
  while :; do
    st=$(api GET /runs/$1 | jq -r .status)
    case $st in completed|failed|cancelled) break ;; esac
    sleep 2
  done
}

echo "# kcap product check $(date -u +%FT%TZ) on $(uname -n), commit ${KCAP_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo ?)}"
docker network create --subnet "$SUBNET" $NET >/dev/null
docker run -d --name kcap-sink --network $NET --ip "$SINK_IP" alpine:3.22 sh -c \
  "for p in $OPEN; do (while true; do nc -l -p \$p >/dev/null 2>&1 </dev/null; done) & done; wait" >/dev/null

echo
echo "## 1. bridge network + scan-network overlay (CZUJKA_KERNEL_CAP=auto)"
"${DC_BRIDGE[@]}" up -d --build --wait >/dev/null 2>&1 || { "${DC_BRIDGE[@]}" logs czujka | tail -30; exit 1; }
docker logs $CZ 2>&1 | grep -i 'kernel packet cap' | sed 's/^/  log: /'
echo "  interfaces: $(docker exec $CZ sh -c 'ls /sys/class/net' | tr '\n' ' ')"
echo "  image size: $(docker image inspect czujka:kcap -f '{{.Size}}' | awk '{printf "%.1f MB", $1/1e6}')"
echo "  /healthz without a session: $(curl -sS $API/healthz | jq -c '{status, kernel_cap}')"
login
echo "  /healthz as admin:          $(api GET /healthz | jq -c '{status, kernel_cap}')"
echo "  GET /settings/safety:       $(api GET /settings/safety | jq -c '{max_pps, kernel_cap}')"
echo "  PUT max_pps=500:            $(api PUT /settings/safety '{"max_pps":500}' | jq -c '{max_pps, kernel_cap}')"
echo "  rule in the kernel:         $(docker exec $CZ nft list table inet czujka_kcap | grep -E 'rate over' | xargs)"
echo "  tables in this namespace:   $(docker exec $CZ nft list tables | tr '\n' ';')"

CZIP=$(docker inspect $CZ -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}")
SCOPE=$(api POST /scopes '{"name":"kcap sink","criticality":1}' | jq -r .id)
api POST /scopes/$SCOPE/targets "{\"text\":\"$SINK_IP\"}" >/dev/null
DEF=$(api GET "/profiles?limit=100" | jq -c '[(.items // .)[] | select(.name | startswith("Domyślny"))][0]')
PJSON=$(echo "$DEF" | jq -c --argjson s "$SCOPE" 'del(.id, .created_at, .updated_at, .next_run_at, .last_run_id) | .name = "kcap 1-20000" | .scope_ids = [$s] | .schedule.enabled = false | .ports = "1-20000" | .rate.max_pps = 500')
PROFILE=$(api POST /profiles "$PJSON" | jq -r .id)
LABIF=$(docker exec $CZ sh -c "ip -o -4 addr 2>/dev/null | awk '/ ${SINK_IP%.*}\\./ {print \$2}'" || true)
[ -n "$LABIF" ] || LABIF=$(docker exec $CZ sh -c "for i in /sys/class/net/*; do n=${i##*/}; [ \$n != lo ] && echo \$n; done" | tail -1)
printf 'FROM alpine:3.22\nRUN apk add --no-cache tcpdump\n' | docker build -q -t kcap-tcpdump:dev - >/dev/null

per_second() {
  awk '/^[0-9]+\./ { split($1, t, "."); n[t[1]]++ } END { for (s in n) print s, n[s] }' "$1" | sort -n |
    awk 'NR == 1 { t0 = $1 } { if ($2 > max) max = $2; if ($2 > 520) printf "  t+%03ds %6d\n", $1 - t0, $2 } END { printf "  seconds: %d, max %d SYN/s\n", NR, max }'
}

run_once() { # label freeze
  local label=$1 freeze=$2
  echo
  echo "### run: $label (freeze $freeze s)"
  docker rm -f kcap-tcpdump >/dev/null 2>&1 || true
  docker run -d --name kcap-tcpdump --network "container:$CZ" --cap-drop ALL --cap-add NET_RAW kcap-tcpdump:dev \
    tcpdump -i "$LABIF" -Q out -nn -tt -l "src host $CZIP and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn" >/dev/null
  sleep 2
  local d0 run
  d0=$(api GET /settings/safety | jq .kernel_cap.dropped)
  run=$(api POST /runs "{\"profile_id\":$PROFILE}" | jq -r .id)
  if [ "$freeze" -gt 0 ]; then
    # freeze the port scan in the middle: wait for an nmap -sS process, then 8 s more
    local i=0
    until docker exec $CZ sh -c "ps -o args | grep -q '[n]map -sS -Pn -p'"; do i=$((i + 1)); [ $i -lt 600 ] || { echo "  no port scan seen"; break; }; sleep 0.2; done
    sleep 3
    docker exec $CZ sh -c "ps -o args | grep '[n]map -sS' | cut -c1-90" | sed 's/^/  frozen: /'
    docker exec $CZ pkill -STOP -f '^/usr/bin/nmap ' && echo "  $(date -u +%T) SIGSTOP nmap" || echo "  no nmap to freeze"
    sleep "$freeze"
    docker exec $CZ pkill -CONT -f '^/usr/bin/nmap ' && echo "  $(date -u +%T) SIGCONT nmap" || echo "  no nmap to resume"
  fi
  wait_run "$run"
  sleep 1
  docker logs kcap-tcpdump 2>/dev/null >"$tmp/syn-$label.txt"
  echo "  SYN packets per second on the scan interface (seconds above 520 listed):"
  per_second "$tmp/syn-$label.txt"
  api GET /runs/$run | jq -c '{id, status, services_open: .stats.services_open, packets_sent: .stats.packets_sent, notes: .stats.notes, warnings: .stats.warnings}' | sed 's/^/  /'
  echo "  kernel counter: before $d0, after $(api GET /settings/safety | jq .kernel_cap.dropped)"
  echo "  services found: $(api GET "/services?limit=200" | jq -r '[(.items // .)[] | .port] | sort | unique | map(tostring) | join(" ")')"
}
for r in ${KCAP_RUNS:-normal freeze}; do
  case $r in normal) run_once normal 0 ;; freeze) run_once freeze "$FREEZE" ;; esac
done
"${DC_BRIDGE[@]}" down >/dev/null 2>&1
docker rm -f kcap-tcpdump >/dev/null 2>&1 || true

if [ -z "${KCAP_SKIP_HOST:-}" ]; then
  echo
  echo "## 2. host network (deploy/docker-compose.host-network.yml), CZUJKA_KERNEL_CAP=require"
  CZUJKA_KERNEL_CAP=require "${DC_HOST[@]}" up -d --wait >/dev/null 2>&1 || { "${DC_HOST[@]}" logs czujka | tail -30; exit 1; }
  docker logs $CZ 2>&1 | grep -i 'kernel packet cap' | sed 's/^/  log: /'
  login
  echo "  /healthz as admin: $(api GET /healthz | jq -c '{status, kernel_cap}')"
  echo "  POST /runs:        $(api POST /runs "{\"profile_id\":$PROFILE}" | jq -c .)"
  echo "  czujka_kcap tables in the host namespace: $(docker exec $CZ nft list tables | grep -c czujka_kcap || true)"
  "${DC_HOST[@]}" down >/dev/null 2>&1
fi
echo
echo "# done"
