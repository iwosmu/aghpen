#!/usr/bin/env bash
# Runs inside the zoo machine (see dind.sh). For one batch: starts its services, waits until each port of the truth
# table answers, scans target "localhost" with a copy of the DEFAULT profile through Czujka's REST API, saves the run's
# JSON export, services, findings and changes, then runs plain "nmap -sV" (the same nmap binary Czujka uses, in its
# container) on the batch ports for comparison, and stops the batch.
#
#   CZ_URL=... CZ_PASSWORD=... ZOO_GW=<docker bridge gateway> bash e2e/zoo/run.sh <batch> <outdir> [nmap]
#
# Safety: the target is "localhost", which Czujka maps to the docker host of the zoo machine (the dind container); the
# operator lock (CZUJKA_ALLOWED_NETWORKS = the gateway /32) keeps every scan inside it. nmap runs only against $ZOO_GW.
set -uo pipefail
cd "$(dirname "$0")/../.."
B=$1; OUT=$2; NMAP=${3:-}
CZ_URL=${CZ_URL:-http://127.0.0.1:18080}; API=$CZ_URL/api/v1
EMAIL=${CZ_EMAIL:-admin@czujka.local}; PW=${CZ_PASSWORD:?set CZ_PASSWORD}
GW=${ZOO_GW:?set ZOO_GW}
TRUTH=e2e/zoo/truth.tsv
JAR=$(mktemp); CSRF=
mkdir -p "$OUT"
log() { echo "[$(date +%H:%M:%S)] $B: $*"; }
api() { if [ $# -ge 3 ]; then curl -sS -b "$JAR" -c "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" -d "$3" "$API$2"
  else curl -sS -b "$JAR" -c "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" "$API$2"; fi; }
CSRF=$(curl -sS -c "$JAR" -H "Content-Type: application/json" -d "$(jq -nc --arg e "$EMAIL" --arg p "$PW" '{email:$e,password:$p}')" "$API/auth/login" | jq -r .csrf_token)
[ -n "$CSRF" ] && [ "$CSRF" != null ] || { echo "login failed at $API"; exit 2; }

SCOPE=$(api GET "/scopes?limit=100" | jq -r '[.items[] | select(.name == "Zoo")][0].id // empty')
if [ -z "$SCOPE" ]; then
  SCOPE=$(api POST /scopes '{"name":"Zoo","criticality":3}' | jq -r .id)
  api POST "/scopes/$SCOPE/targets" '{"text":"localhost"}' >/dev/null
fi
PROF=$(api GET "/profiles?limit=100" | jq -r '[.items[] | select(.name == "Zoo: profil domyślny")][0].id // empty')
if [ -z "$PROF" ]; then
  PROF=$(api GET "/profiles?limit=100" | jq -c '[.items[] | select(.name | startswith("Domyślny"))][0]' | jq -c --argjson s "$SCOPE" \
    'del(.id, .created_at, .updated_at, .next_run_at, .last_run_id) | .name = "Zoo: profil domyślny" | .scope_ids = [$s] | .schedule.enabled = false' \
    | { read -r body; api POST /profiles "$body"; } | jq -r .id)
fi

# Ports of this batch from the truth table: port, proto, ready check.
mapfile -t ROWS < <(awk -F'\t' -v b="$B" '!/^#/ && $1 == b {print $2" "$3" "$NF}' "$TRUTH")
TCP=$(printf '%s\n' "${ROWS[@]}" | awk '$2 == "tcp" {print $1}' | sort -un | paste -sd, -)
UDP=$(printf '%s\n' "${ROWS[@]}" | awk '$2 == "udp" {print $1}' | sort -un | paste -sd, -)

log "starting (tcp $TCP${UDP:+, udp $UDP})"
docker compose -p zoo -f "e2e/zoo/batches/$B.yml" up -d >"$OUT/compose-up.txt" 2>&1 || { cat "$OUT/compose-up.txt"; }
t0=$(date +%s)
while :; do
  missing=
  for r in "${ROWS[@]}"; do
    set -- $r; p=$1; pr=$2; rd=$3
    [ "$pr" = tcp ] || continue
    case $rd in
      http*) path=${rd#http}; c=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p${path:-/}"); case $c in 000|502|503|504) missing="$missing $p" ;; esac ;;
      https*) path=${rd#https}; c=$(curl -sk -m 5 -o /dev/null -w '%{http_code}' "https://127.0.0.1:$p${path:-/}"); case $c in 000|502|503|504) missing="$missing $p" ;; esac ;;
      *) (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null || missing="$missing $p" ;;
    esac
  done
  [ -z "$missing" ] && { log "every port answers after $(( $(date +%s) - t0 )) s"; break; }
  [ $(( $(date +%s) - t0 )) -gt ${ZOO_READY_MAX:-480} ] && { log "not ready after ${ZOO_READY_MAX:-480} s:$missing (scanning anyway)"; break; }
  sleep 5
done
sleep ${ZOO_SETTLE:-20}
docker compose -p zoo -f "e2e/zoo/batches/$B.yml" ps --format '{{.Service}} {{.Image}} {{.Status}} {{.Ports}}' >"$OUT/ps.txt" 2>&1

t0=$(date +%s)
RUN=$(api POST /runs "{\"profile_id\":$PROF}" | jq -r .id)
while :; do
  st=$(api GET "/runs/$RUN" | jq -r .status)
  case $st in completed|failed|cancelled) break ;; esac
  [ $(( $(date +%s) - t0 )) -gt 1800 ] && { api POST "/runs/$RUN/cancel" '{}' >/dev/null; st=timeout; break; }
  sleep 3
done
api GET "/runs/$RUN" >"$OUT/run.json"
api GET "/export/runs/$RUN.json" >"$OUT/export.json"
api GET "/services?run_id=$RUN&limit=1000" >"$OUT/services.json"
api GET "/findings?limit=5000" | jq -c --argjson r "$RUN" '{items: [.items[] | select(.last_run_id == $r)]}' >"$OUT/findings.json"
api GET "/changes?run_id=$RUN&limit=1000" >"$OUT/changes.json"
log "Czujka run $RUN $st in $(( $(date +%s) - t0 )) s: $(jq -c '{hosts: .stats.hosts_up, services: .stats.services_open, warnings: (.warnings // [] | length)}' "$OUT/run.json")"
echo "$RUN $st $(( $(date +%s) - t0 ))" >"$OUT/meta.txt"

if [ -n "$NMAP" ]; then
  t0=$(date +%s)
  ports="T:$TCP${UDP:+,U:$UDP}"
  docker exec czujka-czujka-1 nmap --privileged -sS ${UDP:+-sU} -sV -Pn -n -p "$ports" --host-timeout 15m -oX - "$GW" >"$OUT/nmap.xml" 2>"$OUT/nmap.err"
  log "nmap -sV on $ports: exit $? in $(( $(date +%s) - t0 )) s"
fi

docker compose -p zoo -f "e2e/zoo/batches/$B.yml" logs --no-color --tail 30 >"$OUT/logs.txt" 2>&1
[ "${ZOO_KEEP_BATCH:-0}" = 1 ] || docker compose -p zoo -f "e2e/zoo/batches/$B.yml" down -v --remove-orphans >/dev/null 2>&1
rm -f "$JAR"
