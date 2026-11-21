#!/usr/bin/env bash
# Prepares a local Czujka stack on the lab network for a first-cut recording of the demo video.
#
#   docs/demo/seed.sh            start stack "czpitch" on port 18640, configure it, run two full scans of the lab
#
# It does not change the state of the lab (no lab/scenario.sh): it only scans 10.66.0.0/16.
# It also starts a profile that scans the unstable hosts 10.66.70.0/24 every 2 minutes, and turns
# re-probing on, so the host detail has a rhythm and a re-probe plan to show.
# Environment: SEED_PROJECT (czpitch), SEED_PORT (18640), SEED_RUNS (2), CZ_PASSWORD (admin password; default: generated
# and saved to docs/demo/out/.seed-<project>.pw, which git ignores).
set -euo pipefail
cd "$(dirname "$0")/../.."
PROJECT=${SEED_PROJECT:-czpitch}
PORT=${SEED_PORT:-18640}
RUNS=${SEED_RUNS:-2}
API=http://127.0.0.1:$PORT/api/v1
mkdir -p docs/demo/out
PWFILE=docs/demo/out/.seed-$PROJECT.pw
if [ -z "${CZ_PASSWORD:-}" ]; then
  if [ -f "$PWFILE" ]; then CZ_PASSWORD=$(cat "$PWFILE"); else CZ_PASSWORD="Demo-$(date +%s)-$RANDOM$RANDOM"; fi
fi
echo "$CZ_PASSWORD" > "$PWFILE"
JAR=docs/demo/out/.jar-$PROJECT
CSRF=
log() { echo "[$(date +%H:%M:%S)] $*"; }
api() {
  if [ $# -ge 3 ]; then curl -fsS -b "$JAR" -c "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" -d "$3" "$API$2"
  else curl -fsS -b "$JAR" -c "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" "$API$2"; fi
}

if ! curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
  log "starting the product: project $PROJECT, port $PORT, on the lab network czujka-lab"
  CZUJKA_VERSION=${CZUJKA_VERSION:-$PROJECT} CZUJKA_PORT=$PORT CZUJKA_SCAN_NETWORK=czujka-lab CZUJKA_ADMIN_PASSWORD="$CZ_PASSWORD" \
  CZUJKA_ALLOWED_NETWORKS=10.66.0.0/16 \
    docker compose -p "$PROJECT" -f deploy/docker-compose.yml -f deploy/docker-compose.scan-network.yml up -d --build --wait
fi
CSRF=$(curl -fsS -c "$JAR" -H "Content-Type: application/json" -d "{\"email\":\"admin@czujka.local\",\"password\":\"$CZ_PASSWORD\"}" "$API/auth/login" | jq -r .csrf_token)

# Every Czujka container on the lab network (ours and other stacks) and the gateway are excluded.
EXCL=$(docker network inspect czujka-lab | jq -c '[.[0].Containers[] | select(.Name | test("czujka-1$")) | .IPv4Address | sub("/.*"; "")] + ["10.66.0.1"]')
POL=$(api GET /settings/safety | jq -c --argjson e "$EXCL" '.exclusions = ($e + .exclusions | unique) | .allowed_networks = ["10.66.0.0/16"] | .max_pps = 2000')
api PUT /settings/safety "$POL" | jq -c '{max_pps, exclusions}'
api PUT /settings/reprobe '{"enabled":true}' | jq -c '{enabled, budget_per_hour, backoff_minutes}'

scope() { # name text -> id
  local id
  id=$(api GET "/scopes?limit=100" | jq -r --arg n "$1" '[.items[] | select(.name == $n)][0].id // empty')
  if [ -z "$id" ]; then
    id=$(api POST /scopes "$(jq -nc --arg n "$1" '{name: $n, criticality: 3}')" | jq -r .id)
    api POST "/scopes/$id/targets" "$(jq -nc --arg t "$2" '{text: $t}')" >/dev/null
  fi
  echo "$id"
}
LAB=$(scope "Laboratorium /16" "$(cat lab/ground-truth/targets-cidr.txt lab/ground-truth/targets-domains.txt)")
FLAP=$(scope "Laboratorium: hosty niestabilne" "10.66.70.0/24")
DEF=$(api GET "/profiles?limit=100" | jq -c '[(.items // .)[] | select(.name | startswith("Domyślny"))][0]')
profile() { # name scope schedule-json -> id
  local id
  id=$(api GET "/profiles?limit=100" | jq -r --arg n "$1" '[(.items // .)[] | select(.name == $n)][0].id // empty')
  if [ -z "$id" ]; then
    id=$(api POST /profiles "$(echo "$DEF" | jq -c --arg n "$1" --argjson s "$2" --argjson sch "$3" \
      'del(.id, .created_at, .updated_at, .next_run_at, .last_run_id) | .name = $n | .scope_ids = [$s] | .schedule = (.schedule * $sch) | .rate.max_pps = 1500 | .rate.max_parallel_chunks = 4')" | jq -r .id)
  fi
  echo "$id"
}
FULL=$(profile "Laboratorium /16: pełny przegląd" "$LAB" '{"enabled":false}')
profile "Co 2 minuty: hosty niestabilne" "$FLAP" '{"enabled":true,"cron":"*/2 * * * *","interval_minutes":0}' >/dev/null

for i in $(seq 1 "$RUNS"); do
  RUN=$(api POST /runs "{\"profile_id\":$FULL}" | jq -r .id)
  log "full scan $i/$RUNS: run $RUN"
  while :; do
    S=$(api GET "/runs/$RUN" | jq -r .status)
    case "$S" in completed|failed|cancelled) break ;; esac
    sleep 5
  done
  log "run $RUN $S: $(api GET "/runs/$RUN" | jq -c '{hosts_up: .stats.hosts_up, services: .stats.services_open, elapsed: .stats.elapsed_sec}')"
done
log "ready: http://127.0.0.1:$PORT (admin@czujka.local, password in $PWFILE)"
