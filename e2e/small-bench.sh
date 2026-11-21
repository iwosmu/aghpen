#!/usr/bin/env bash
# Small-scope speed bench (point B of the jury template work): one "jury host" with
# several services, scanned through the product's REST API.
#
#   CZUJKA_VERSION=acc10 e2e/small-bench.sh
#   SB_ONLY="seven top1000" e2e/small-bench.sh
#
# The jury host is one network namespace on the lab network czujka-lab at $SB_HOST
# (default 10.66.251.10, not a lab host): an anchor container holds the address and
# the service containers join it, so all ports answer on one IP, like the template's
# single machine. Nothing is published on the docker host and nothing of the docker
# host is scanned. Do not run it beside e2e/lab-gate.sh: the jury host would be an
# extra host in the /16. It removes the jury host at the end (SB_KEEP_TARGETS=1 keeps it).
# Profiles: seven (7 named ports), top1000, full (1-65535). For each: wall time from
# POST /runs to "completed", time until the first service is visible in GET /services,
# services found, and the packets the product sent in one-second bins (e2e/ppsbins).
set -uo pipefail
cd "$(dirname "$0")/.."
export CZUJKA_VERSION=${CZUJKA_VERSION:-acc9}
OUT=${SB_OUT:-e2e/out/small-bench-$CZUJKA_VERSION}
PORT=18530 PROJECT=${SB_PROJECT:-czacc} # reuses the project's networks: the docker host may have no free address pool
BASE=http://127.0.0.1:$PORT API=$BASE/api/v1
mkdir -p "$OUT"; JAR=$OUT/.jar
ADMIN=admin@czujka.local ADMIN_PW="Sb-$(date +%s)-$RANDOM$RANDOM"
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }
api() { curl -sS -b "$JAR" -c "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" ${3:+-d "$3"} "$API$2"; }

# ---- jury host: one IP, seven services ----
HOST=${SB_HOST:-10.66.251.10}
SEVEN=80,8888,5672,15672,3000,22,5432
if [ -z "$(docker ps -q --filter name=^czsb-host$)" ]; then
  docker rm -f czsb-host czsb-httpd czsb-rabbit czsb-gitea czsb-pg >/dev/null 2>&1
  docker run -d --name czsb-host --network czujka-lab --ip "$HOST" nginx:alpine >/dev/null
  docker run -d --name czsb-httpd --network container:czsb-host httpd:alpine \
    sh -c "sed -i 's/^Listen 80$/Listen 8888/' /usr/local/apache2/conf/httpd.conf && exec httpd-foreground" >/dev/null
  docker run -d --name czsb-rabbit --network container:czsb-host rabbitmq:4.3.8-management-alpine >/dev/null
  docker run -d --name czsb-gitea --network container:czsb-host gitea/gitea:latest >/dev/null
  docker run -d --name czsb-pg --network container:czsb-host -e POSTGRES_PASSWORD=bench-only postgres:17-alpine >/dev/null
  sleep ${SB_TARGET_WAIT:-30}
fi

# ---- product ----
export CZUJKA_PORT=$PORT CZUJKA_ADMIN_EMAIL=$ADMIN CZUJKA_ADMIN_PASSWORD=$ADMIN_PW CZUJKA_SCHED_INTERVAL=10s CZUJKA_TZ=Europe/Warsaw
export CZUJKA_SCAN_NETWORK=czujka-lab LR_IP=${LR_IP:-10.66.0.30}
DC="docker compose -p $PROJECT -f deploy/docker-compose.yml -f deploy/docker-compose.scan-network.yml -f e2e/lab-run.compose.yml"
$DC down -v --remove-orphans >/dev/null 2>&1
$DC up -d --wait > "$OUT/compose.log" 2>&1 || { tail -20 "$OUT/compose.log"; exit 1; }
CZ=$PROJECT-czujka-1
CSRF=$(curl -sS -c "$JAR" -H "Content-Type: application/json" -d "{\"email\":\"$ADMIN\",\"password\":\"$ADMIN_PW\"}" $API/auth/login | jq -r .csrf_token)
SCOPE=$(api POST /scopes "{\"name\":\"bench host\",\"targets\":[\"$HOST\"]}" | jq -r .id)
DEF=$(api GET "/profiles?limit=50" | jq -c '[.items[]][0] | del(.id, .created_at, .updated_at, .last_run_id, .next_run_at)')
SRC=$LR_IP
IF=$(docker exec "$CZ" sh -c "ip -o -4 addr | awk '/ 10\\.66\\./ {print \$2}'")
echo "| profil | porty | czas do 1. usługi [s] | czas przebiegu [s] | usługi | maks. pps (wszystko) / limit | sekundy ponad limit |" > "$OUT/table.md"
echo "| --- | --- | --- | --- | --- | --- | --- |" >> "$OUT/table.md"
for v in ${SB_ONLY:-seven top1000 full}; do
  case $v in seven) P=$SEVEN ;; top1000) P=top-1000 ;; full) P=1-65535 ;; esac
  PROF=$(echo "$DEF" | jq -c --arg p "$P" --arg n "bench $v $(date +%s)" --argjson s "$SCOPE" '.name=$n | .ports=$p | .scope_ids=[$s] | .udp.enabled=false | .schedule.enabled=false')
  PID=$(api POST /profiles "$PROF" | jq -r .id)
  docker rm -f czsb-td >/dev/null 2>&1
  docker run -d --name czsb-td --network "container:$CZ" --cap-add NET_RAW --cap-add NET_ADMIN czfull-tcpdump:latest tcpdump -i "$IF" -n -tt -l "src host $SRC or arp" >/dev/null
  sleep 1
  T0=$(python3 -c 'import time; print(time.time())' 2>/dev/null || date +%s)
  RUN=$(api POST /runs "{\"profile_id\":$PID}" | jq -r .id)
  FIRST=""
  while :; do
    R=$(api GET /runs/$RUN); ST=$(echo "$R" | jq -r .status)
    NOW=$(python3 -c 'import time; print(time.time())' 2>/dev/null || date +%s)
    if [ -z "$FIRST" ] && [ "$(api GET "/services?run_id=$RUN&limit=1" | jq '.total // (.items | length)')" -gt 0 ]; then FIRST=$(echo "$NOW - $T0" | bc); fi
    case $ST in completed|failed|cancelled) break ;; esac
    sleep 0.5
  done
  WALL=$(echo "$NOW - $T0" | bc)
  sleep 1; docker logs czsb-td > "$OUT/tcpdump-$v.txt" 2>/dev/null; docker rm -f czsb-td >/dev/null
  CAP=$(echo "$PROF" | jq .rate.max_pps)
  go run ./e2e/ppsbins -src "$SRC" -cap "$CAP" -json "$OUT/tcpdump-$v.txt" > "$OUT/pps-$v.json"
  echo "$R" | jq . > "$OUT/run-$v.json"
  api GET "/services?run_id=$RUN&limit=500" > "$OUT/services-$v.json"
  N=$(jq '.stats.services_open' "$OUT/run-$v.json")
  printf '| %s | %s | %s | %.1f | %s | %s / %s | %s |\n' "$v" "$P" "${FIRST:-–}" "$WALL" "$N" "$(jq .all_max_per_s "$OUT/pps-$v.json")" "$CAP" "$(jq .all_seconds_over_cap "$OUT/pps-$v.json")" | tee -a "$OUT/table.md"
done
log "status $ST; output $OUT"
[ "${SB_KEEP:-0}" = 1 ] || $DC down -v --remove-orphans >/dev/null 2>&1
[ "${SB_KEEP_TARGETS:-0}" = 1 ] || docker rm -f czsb-host czsb-httpd czsb-rabbit czsb-gitea czsb-pg >/dev/null 2>&1
cat "$OUT/table.md"
