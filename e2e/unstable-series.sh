#!/usr/bin/env bash
# A series of scheduled scans of the unstable lab hosts, through the REST API.
# It shows what Czujka reports for them over time: retries inside a run,
# host_missing, unstable, expected, host_gone.
#
#   e2e/unstable-series.sh                              25 minutes, default availability clock
#   US_MINUTES=60 US_BUCKET=3m US_PERIOD=30m US_PROJECT=czus2 US_PORT=18522 US_IP=10.66.0.32 e2e/unstable-series.sh
#                                                       the same with a lab clock (CZUJKA_AVAIL_BUCKET/PERIOD)
#
# Scope: flapper 10.66.70.20, tod-office 10.66.70.21, tod-night 10.66.70.22 and,
# as a stable control, no-icmp 10.66.70.10. Profile: the seeded default with
# port 80 only, no version detection, no HTTP, ARP discovery, and a schedule of
# one run per minute (the lab compresses an hour into a minute). The scheduler
# of the product starts the runs. Output: $US_OUT/series.md (timeline against the
# lab's availability rule) and the raw JSON of every run.
set -uo pipefail
cd "$(dirname "$0")/.."
PROJECT=${US_PROJECT:-czus}
PORT=${US_PORT:-18521}
IP=${US_IP:-10.66.0.31}
MINUTES=${US_MINUTES:-25}
OUT=${US_OUT:-e2e/out/unstable-$PROJECT-$(date +%Y%m%d-%H%M%S)}
BASE=http://127.0.0.1:$PORT
API=$BASE/api/v1
ADMIN=admin@czujka.local
ADMIN_PW="Series-$(date +%s)-$RANDOM$RANDOM"
mkdir -p "$OUT/runs"
JAR=$OUT/.jar
CSRF=
export LR_IP=$IP CZUJKA_PORT=$PORT CZUJKA_VERSION=${CZUJKA_VERSION:-acc} CZUJKA_ADMIN_EMAIL=$ADMIN CZUJKA_ADMIN_PASSWORD=$ADMIN_PW
export CZUJKA_SCHED_INTERVAL=5s CZUJKA_SCAN_NETWORK=czujka-lab CZUJKA_TZ=Europe/Warsaw
export CZUJKA_AVAIL_BUCKET=${US_BUCKET:-} CZUJKA_AVAIL_PERIOD=${US_PERIOD:-}
DC="docker compose -p $PROJECT -f deploy/docker-compose.yml -f deploy/docker-compose.scan-network.yml -f e2e/lab-run.compose.yml"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }
api() {
  local out code
  if [ $# -ge 3 ]; then
    out=$(curl -sS -b "$JAR" -c "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" -d "$3" -w "\n%{http_code}" "$API$2")
  else
    out=$(curl -sS -b "$JAR" -c "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" -w "\n%{http_code}" "$API$2")
  fi
  code=${out##*$'\n'}
  if [ "$code" -ge 400 ]; then echo "HTTP $code for $1 $2: ${out%$'\n'*}" >&2; return 1; fi
  printf "%s" "${out%$'\n'*}"
}

log "starting the product (project $PROJECT, port $PORT, lab address $IP, clock bucket=${US_BUCKET:-1h} period=${US_PERIOD:-168h})"
$DC down -v --remove-orphans >/dev/null 2>&1 || true
if [ "${US_SKIP_BUILD:-1}" = 1 ]; then $DC up -d --wait >"$OUT/compose.log" 2>&1; else $DC up -d --build --wait >"$OUT/compose.log" 2>&1; fi || { tail -20 "$OUT/compose.log"; exit 1; }
LOGIN=$(curl -sS -c "$JAR" -H "Content-Type: application/json" -d "{\"email\":\"$ADMIN\",\"password\":\"$ADMIN_PW\"}" $API/auth/login)
CSRF=$(echo "$LOGIN" | jq -r .csrf_token)
POL=$(api GET /settings/safety | jq -c --arg ip "$IP" '.exclusions = ([$ip, "10.66.0.1"] + .exclusions | unique)')
api PUT /settings/safety "$POL" >/dev/null
SCOPE=$(api POST /scopes '{"name":"Hosty niestabilne (seria)","criticality":2}' | jq -r .id)
api POST /scopes/$SCOPE/targets "$(jq -nc '{text: "10.66.70.10\n10.66.70.20\n10.66.70.21\n10.66.70.22"}')" | jq -c '{saved: (.valid | length)}' >/dev/null
DEF=$(api GET "/profiles?limit=100" | jq -c '[(.items // .)[] | select(.name | startswith("Domyślny"))][0]')
PJSON=$(echo "$DEF" | jq -c --argjson s "$SCOPE" 'del(.id, .created_at, .updated_at, .next_run_at, .last_run_id) | .name = "seria: hosty niestabilne" | .scope_ids = [$s]
  | .ports = "80" | .service_detection = false | .http.enabled = false | .udp.enabled = false | .discovery.arp = true
  | .schedule = {enabled: true, interval_minutes: 1, timezone: "Europe/Warsaw"}')
PROFILE=$(api POST /profiles "$PJSON" | jq -r .id)
echo "$PJSON" | jq . > "$OUT/profile.json"
log "profile $PROFILE: one run per minute for $MINUTES minutes, retry $(echo "$PJSON" | jq -c .retry)"
END=$(( $(date +%s) + MINUTES * 60 ))
seen=" "
while [ "$(date +%s)" -lt "$END" ]; do
  for id in $(api GET "/runs?profile_id=$PROFILE&status=completed&limit=200" | jq -r '.items[].id'); do
    case "$seen" in *" $id "*) continue ;; esac
    seen="$seen$id "
    api GET /runs/$id > "$OUT/runs/run-$id.json"
    curl -sS -b "$JAR" -o "$OUT/runs/export-$id.json" "$API/export/runs/$id.json"
    api GET "/changes?run_id=$id&limit=200" > "$OUT/runs/changes-$id.json"
    api GET "/hosts?limit=100&scope_id=$SCOPE" > "$OUT/runs/hosts-$id.json"
    log "run $id: $(jq -r '[.[] | "\(.ip | split(".") | .[3])=\(if .up then "up" else "--" end)/a\(.attempts)"] | join(" ")' "$OUT/runs/export-$id.json") | $(jq -r '[.items[] | "\(.ip | split(".") | .[3]):\(.status)"] | join(" ")' "$OUT/runs/hosts-$id.json") | changes: $(jq -r '[.items[] | "\(.kind)\(if .expected then "(expected)" else "" end) \(.ip | split(".") | .[3])"] | join(", ")' "$OUT/runs/changes-$id.json")"
  done
  sleep 10
done
api PATCH /profiles/$PROFILE '{"schedule":{"enabled":false,"interval_minutes":1,"timezone":"Europe/Warsaw"}}' >/dev/null
for h in $(api GET "/hosts?limit=100&scope_id=$SCOPE" | jq -r '.items[] | "\(.id):\(.ip)"'); do
  api GET /hosts/${h%%:*}/availability > "$OUT/availability-${h##*:}.json"
done
go run ./e2e/unstableseries -dir "$OUT" -truth lab/ground-truth/t0.json -clock "${US_BUCKET:-1h}/${US_PERIOD:-168h}" > "$OUT/series.md"
tail -25 "$OUT/series.md"
if [ "${US_KEEP:-0}" != 1 ]; then $DC down -v --remove-orphans >/dev/null 2>&1; fi
log "output: $OUT/series.md"
