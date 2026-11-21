#!/usr/bin/env bash
# Slow and broken services (point C of the jury template work): Toxiproxy in
# front of nginx on the lab network, scanned twice through the product's API.
#
#   CZUJKA_VERSION=acc15 e2e/toxi-bench.sh
#
# Toxiproxy (czsb-toxi, ${SB_TOXI:-10.66.251.20}) forwards five ports to nginx on the
# jury host (czsb-host, 10.66.251.10:80):
#   18000 no toxic | 18001 latency 500 ms + jitter 100 ms | 18002 bandwidth 12 KB/s (100 kbit/s)
#   18003 timeout toxic (the connection opens, no data ever comes) | 18004 slow close (5 s)
# Checks: every port open and named in both runs, the run time bounded, and
# response_ms (time to the first byte of the first GET /) stable between runs.
# Nothing is published on the docker host and nothing of it is scanned. Do not
# run it beside e2e/lab-gate.sh (two extra hosts in the /16).
set -uo pipefail
cd "$(dirname "$0")/.."
export CZUJKA_VERSION=${CZUJKA_VERSION:-acc15}
OUT=${TB_OUT:-e2e/out/toxi-bench-$CZUJKA_VERSION}
PORT=18530 PROJECT=${SB_PROJECT:-czacc}
API=http://127.0.0.1:$PORT/api/v1
TOXI=${SB_TOXI:-10.66.251.20} HOST=10.66.251.10
mkdir -p "$OUT"; JAR=$OUT/.jar
ADMIN=admin@czujka.local ADMIN_PW="Tb-$(date +%s)-$RANDOM$RANDOM"
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }
api() { curl -sS -b "$JAR" -c "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" ${3:+-d "$3"} "$API$2"; }

# ---- targets ----
if [ -z "$(docker ps -q --filter name=^czsb-host$)" ]; then
  docker rm -f czsb-host >/dev/null 2>&1
  docker run -d --name czsb-host --network czujka-lab --ip "$HOST" nginx:alpine >/dev/null 2>&1; docker start czsb-host >/dev/null 2>&1
fi
docker rm -f czsb-toxi >/dev/null 2>&1
docker run -d --name czsb-toxi --network czujka-lab --ip "$TOXI" ghcr.io/shopify/toxiproxy:2.12.0 >/dev/null 2>&1; docker start czsb-toxi >/dev/null 2>&1
sleep 3
T() { docker exec czsb-toxi /toxiproxy-cli "$@" >/dev/null; }
for p in 18000 18001 18002 18003 18004 18005; do T create -l 0.0.0.0:$p -u $HOST:80 p$p; done
T toxic add -t latency -a latency=500 -a jitter=100 p18001
T toxic add -t bandwidth -a rate=12 p18002
T toxic add -t timeout -a timeout=0 p18003
T toxic add -t slow_close -a delay=5000 p18004
T toxic add -t timeout -a timeout=1000 p18005
docker exec czsb-toxi /toxiproxy-cli list | tee "$OUT/toxics.txt"
# the template's modern-proxy shape: Traefik v3.1 (web :80 to toxiproxy 18005 with a
# 1 s timeout toxic, insecure API :8080), at TRAEFIK (10.66.251.21)
TRAEFIK=10.66.251.21
mkdir -p "$OUT/traefik"
cat > "$OUT/traefik/route.yml" <<EOF
http:
  routers:
    site: {entryPoints: [web], rule: "PathPrefix(\`/\`)", service: site}
  services:
    site: {loadBalancer: {servers: [{url: "http://$TOXI:18005"}]}}
EOF
docker rm -f czsb-traefik >/dev/null 2>&1
docker run -d --name czsb-traefik --network czujka-lab --ip $TRAEFIK -v "$PWD/$OUT/traefik:/etc/traefik/dynamic:ro" traefik:v3.1 \
  --api.dashboard=true --api.insecure=true --providers.file.directory=/etc/traefik/dynamic --entrypoints.web.address=:80 >/dev/null 2>&1
docker start czsb-traefik >/dev/null 2>&1

# ---- product ----
export CZUJKA_PORT=$PORT CZUJKA_ADMIN_EMAIL=$ADMIN CZUJKA_ADMIN_PASSWORD=$ADMIN_PW CZUJKA_SCHED_INTERVAL=10s CZUJKA_TZ=Europe/Warsaw
export CZUJKA_SCAN_NETWORK=czujka-lab LR_IP=${LR_IP:-10.66.0.30}
DC="docker compose -p $PROJECT -f deploy/docker-compose.yml -f deploy/docker-compose.scan-network.yml -f e2e/lab-run.compose.yml"
$DC down -v --remove-orphans >/dev/null 2>&1
$DC up -d --wait > "$OUT/compose.log" 2>&1 || { tail -20 "$OUT/compose.log"; exit 1; }
CSRF=$(curl -sS -c "$JAR" -H "Content-Type: application/json" -d "{\"email\":\"$ADMIN\",\"password\":\"$ADMIN_PW\"}" $API/auth/login | jq -r .csrf_token)
SCOPE=$(api POST /scopes '{"name":"toxiproxy","criticality":3}' | jq -r .id)
api POST /scopes/$SCOPE/targets "{\"text\":\"$TOXI\n$TRAEFIK\"}" >/dev/null
DEF=$(api GET "/profiles?limit=50" | jq -c '[.items[]][0] | del(.id, .created_at, .updated_at, .last_run_id, .next_run_at)')
PROF=$(echo "$DEF" | jq -c --argjson s "$SCOPE" '.name="toxiproxy" | .ports="80,8080,18000-18005" | .scope_ids=[$s] | .udp.enabled=false | .schedule.enabled=false')
PID=$(api POST /profiles "$PROF" | jq -r .id)
for n in 1 2; do
  T0=$(date +%s)
  RUN=$(api POST /runs "{\"profile_id\":$PID}" | jq -r .id)
  while :; do ST=$(api GET /runs/$RUN | jq -r .status); case $ST in completed|failed|cancelled|"") break ;; esac; sleep 1; done
  echo "$(( $(date +%s) - T0 ))" > "$OUT/wall-$n.txt"
  api GET "/services?run_id=$RUN&limit=50" > "$OUT/services-$n.json"
  api GET /runs/$RUN > "$OUT/run-$n.json"
  log "run $n ($RUN): $ST in $(cat "$OUT/wall-$n.txt") s"
done
{
echo "| port | toxic | stan | nazwa | HTTP | technologie | response_ms (1) | response_ms (2) |"
echo "| --- | --- | --- | --- | --- | --- | --- | --- |"
for hp in $TOXI:18000 $TOXI:18001 $TOXI:18002 $TOXI:18003 $TOXI:18004 $TOXI:18005 $TRAEFIK:80 $TRAEFIK:8080; do
  ip=${hp%:*} p=${hp#*:}
  case $hp in *:18000) t="brak" ;; *:18001) t="opóźnienie 500 ms ± 100 ms" ;; *:18002) t="przepustowość 12 KB/s" ;; *:18003) t="timeout (brak danych)" ;; *:18004) t="wolne zamknięcie 5 s" ;; *:18005) t="timeout 1 s" ;; *:80) t="Traefik → timeout 1 s" ;; *:8080) t="Traefik API" ;; esac
  q='[.items[] | select(.port == $p and ((.ip // .host_ip // $ip) == $ip))][0]'
  a=$(jq -r --argjson p $p --arg ip $ip "$q"' | "\(.state // "–") | \(.name // "–") | \(.http_status // .http.status // "–") | \([.technologies[]?.name] | join(",")) | \(.response_ms // .http.response_ms // "–")"' "$OUT/services-1.json")
  b=$(jq -r --argjson p $p --arg ip $ip "$q"' | "\(.response_ms // .http.response_ms // "–")"' "$OUT/services-2.json")
  echo "| $hp | $t | $a | $b |"
done
echo
echo "czas przebiegu: $(cat "$OUT/wall-1.txt") s i $(cat "$OUT/wall-2.txt") s; usługi: $(jq .stats.services_open "$OUT/run-1.json") i $(jq .stats.services_open "$OUT/run-2.json"); zmiany w 2. przebiegu: $(api GET "/changes?run_id=$RUN&limit=50" | jq -c '[.items[]? | "\(.kind) \(.ip):\(.port)"] ')"
} | tee "$OUT/table.md"
[ "${TB_KEEP:-0}" = 1 ] || { $DC down -v --remove-orphans >/dev/null 2>&1; docker rm -f czsb-toxi czsb-traefik >/dev/null 2>&1; }
