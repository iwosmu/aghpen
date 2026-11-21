#!/usr/bin/env bash
# Measures Czujka on the 70-host lab, through the REST API only.
#
#   e2e/lab-run.sh                     t0, t1, t2 with the profile the product seeds
#   LR_STATES="t0" e2e/lab-run.sh      one state only
#   LR_PROFILE='{"ports":"top-1000"}' LR_NAME=top1000 e2e/lab-run.sh
#                                      the seeded profile with these fields replaced
#
# Steps: lab/lab.sh up (when the lab is not running) and lab/scenario.sh per state;
# the product from deploy/docker-compose.yml joins the lab network czujka-lab at
# $LR_IP; login; safety policy (Czujka's own address and the gateway excluded);
# scope with 10.66.0.0/16 and the 73 lab domain names; the custom signature
# lab/custom-signatures/infokiosk.yaml; a profile; then for each state: scan,
# export (/export/runs/{id}.json), the product's change list (/changes), and
# e2e/score against lab/ground-truth. From the second state on it also scores
# the changes twice: the diff of the two exports and the product's own change list.
#
# It scans only 10.66.0.0/16 (the lab). Output: $LR_OUT (default e2e/out/lab-run-<name>-<time>).
# Environment: LR_PROJECT (czacc), LR_PORT (18520), LR_IP (10.66.0.30), LR_STATES ("t0 t1 t2"),
# LR_PROFILE (JSON merged into the seeded profile), LR_NAME, LR_SKIP_BUILD=1, LR_KEEP=1 (keep the product),
# LR_FINAL_STATE (state to leave the lab in, default t0), LR_FRESH=0 (reuse the running product and its database),
# LR_IGNORE_NEIGH=1 (run even when the Docker host's neighbour table is nearly full; see e2e/neigh-check.sh),
# LR_SECOND="10.66.10.0/24" (a second run with its own scope and a copy of the profile, started LR_SECOND_AFTER
# seconds, default 60, after each main run: the packet rate on the wire must stay under the policy cap for both).
set -uo pipefail
cd "$(dirname "$0")/.."
PROJECT=${LR_PROJECT:-czacc}
PORT=${LR_PORT:-18520}
LR_IP=${LR_IP:-10.66.0.30}
STATES=${LR_STATES:-t0 t1 t2}
NAME=${LR_NAME:-default}
OUT=${LR_OUT:-e2e/out/lab-run-$NAME-$(date +%Y%m%d-%H%M%S)}
BASE=http://127.0.0.1:$PORT
API=$BASE/api/v1
ADMIN=admin@czujka.local
PWFILE=e2e/out/.lab-run-$PROJECT.pw
mkdir -p "$OUT" e2e/out
if [ "${LR_FRESH:-1}" = 0 ] && [ -f "$PWFILE" ]; then ADMIN_PW=$(cat "$PWFILE"); else ADMIN_PW="Lab-$(date +%s)-$RANDOM$RANDOM"; fi
JAR=$OUT/.jar
CSRF=
export LR_IP CZUJKA_PORT=$PORT CZUJKA_VERSION=${CZUJKA_VERSION:-acc} CZUJKA_ADMIN_EMAIL=$ADMIN CZUJKA_ADMIN_PASSWORD=$ADMIN_PW
export CZUJKA_SCHED_INTERVAL=10s CZUJKA_SCAN_NETWORK=czujka-lab CZUJKA_TZ=Europe/Warsaw
DC="docker compose -p $PROJECT -f deploy/docker-compose.yml -f deploy/docker-compose.scan-network.yml -f e2e/lab-run.compose.yml"
CZ=$PROJECT-czujka-1
IGNORE=$(seq -s, -f "10.66.0.%g" 1 49)

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }
api() { # method path [json]; prints the body; returns 1 on an HTTP error
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
mem_sampler() { # memory of the Czujka container every 2 s while $OUT/.mem.on exists
  touch "$OUT/.mem.on"
  ( while [ -f "$OUT/.mem.on" ]; do
      echo "$(date +%s) $(docker stats --no-stream --format '{{.MemUsage}}' "$CZ" 2>/dev/null | awk '{print $1}')" >> "$OUT/mem.txt"; sleep 2
    done ) &
}
mem_max() {
  awk '{v=$2; u=v; gsub(/[0-9.]/,"",u); gsub(/[^0-9.]/,"",v); if(u=="GiB")v*=1024; if(u=="KiB")v/=1024; if(u=="B")v/=1048576; if(v>m)m=v} END{printf "%.1f", m}' "$OUT/mem.txt"
}
txp() { docker exec "$CZ" sh -c "cat /sys/class/net/\$(ip -o -4 addr | awk '/ 10\\.66\\./ {print \$2}')/statistics/tx_packets"; }

# ---- lab ----
if [ "$(docker ps -q --filter name=czujka-lab-kiosk-1 | wc -l)" -eq 0 ]; then
  log "lab is not running: lab/lab.sh up"
  lab/lab.sh up 2>&1 | tail -2
fi

# ---- product ----
if [ "${LR_FRESH:-1}" != 0 ] || ! curl -fsS "$BASE/healthz" >/dev/null 2>&1; then
  log "starting the product (project $PROJECT, port $PORT, lab address $LR_IP)"
  echo "$ADMIN_PW" > "$PWFILE"
  $DC down -v --remove-orphans >/dev/null 2>&1 || true
  if [ "${LR_SKIP_BUILD:-0}" = 1 ]; then $DC up -d --wait >"$OUT/compose.log" 2>&1
  else $DC up -d --build --wait >"$OUT/compose.log" 2>&1; fi || { tail -30 "$OUT/compose.log"; exit 1; }
fi
curl -sS "$BASE/healthz" | jq -c '{status, version}' | tee -a "$OUT/run.log"
LOGIN=$(curl -sS -c "$JAR" -H "Content-Type: application/json" -d "{\"email\":\"$ADMIN\",\"password\":\"$ADMIN_PW\"}" $API/auth/login)
CSRF=$(echo "$LOGIN" | jq -r .csrf_token)
[ -n "$CSRF" ] && [ "$CSRF" != null ] || { echo "login failed: $LOGIN"; exit 1; }

# ---- policy, scope, signature, profile ----
# 10.66.0.1-10.66.0.49: the gateway and the addresses the lab keeps for scanners (lab/README.md, section 4).
# Other workers' scanners stand there; they are not lab hosts.
# A profile cap above the policy cap (LR_PROFILE '{"rate":{"max_pps":2000}}') raises the policy cap with it.
WANTPPS=$(printf '%s' "${LR_PROFILE:-}" | jq '.rate.max_pps // 0' 2>/dev/null)
POL=$(api GET /settings/safety | jq -c --argjson w "${WANTPPS:-0}" '.exclusions = (["10.66.0.1-10.66.0.49"] + .exclusions | unique) | .max_pps = ([.max_pps, $w] | max)')
api PUT /settings/safety "$POL" | jq -c '{max_pps, max_http_rps, max_per_host_rps, exclusions}' | tee -a "$OUT/run.log"
SCOPE=$(api GET "/scopes?limit=100" | jq -r '[.items[] | select(.name == "Laboratorium (lab-run)")][0].id // empty')
if [ -z "$SCOPE" ]; then
  SCOPE=$(api POST /scopes '{"name":"Laboratorium (lab-run)","description":"sieć czujka-lab 10.66.0.0/16 i nazwy z lab/ground-truth/targets-domains.txt","criticality":3}' | jq -r .id)
  # LR_SCOPE replaces the targets (for example "10.66.0.0/20" for a short rate check)
  if [ -n "${LR_SCOPE:-}" ]; then TEXT=$LR_SCOPE; else TEXT=$(cat lab/ground-truth/targets-cidr.txt lab/ground-truth/targets-domains.txt); fi
  api POST /scopes/$SCOPE/targets "$(jq -nc --arg t "$TEXT" '{text: $t}')" | jq -c '{saved: (.valid | length), address_count, excluded, invalid: (.invalid | length)}' | tee -a "$OUT/run.log"
fi
if ! api GET "/signatures?q=lab-infokiosk" | jq -e '.items | length > 0' >/dev/null; then
  api POST /signatures "$(jq -nc --rawfile y lab/custom-signatures/infokiosk.yaml '{yaml: $y, enabled: true}')" | jq -c '{id, slug, enabled}' | tee -a "$OUT/run.log"
fi
DEF=$(api GET "/profiles?limit=100" | jq -c '[(.items // .)[] | select(.name | startswith("Domyślny"))][0]')
[ -n "$DEF" ] && [ "$DEF" != null ] || { echo "no seeded default profile"; exit 1; }
OVER=${LR_PROFILE:-}
[ -n "$OVER" ] || OVER='{}'
PJSON=$(echo "$DEF" | jq -c --argjson s "$SCOPE" --argjson over "$OVER" --arg n "lab-run: $NAME $(date +%H%M%S)" \
  'del(.id, .created_at, .updated_at, .next_run_at, .last_run_id) | .name = $n | .scope_ids = [$s] | .schedule.enabled = false | . * $over')
echo "$PJSON" | jq . > "$OUT/profile.json"
PROFILE=$(api POST /profiles "$PJSON" | jq -r .id)
case "$PROFILE" in ''|null) echo "the profile could not be created"; exit 1 ;; esac
log "profile $PROFILE: $(echo "$PJSON" | jq -c '{ports, discovery, udp, version_intensity, rate, retry}')"
api POST /profiles/$PROFILE/estimate | jq -c . | tee -a "$OUT/run.log"

# ---- runs ----
# The neighbour table is global for the whole Docker host; a nearly full table
# loses hosts and ports in every scan on the machine (e2e/neigh-check.sh).
if ! NB=$(e2e/neigh-check.sh); then
  log "$NB"
  [ "${LR_IGNORE_NEIGH:-0}" = 1 ] || { log "the neighbour table is nearly full: results would be wrong (LR_IGNORE_NEIGH=1 runs anyway)"; exit 3; }
fi
log "before: $NB"
log "load average at the start: $(sysctl -n vm.loadavg 2>/dev/null || cut -d' ' -f1-3 /proc/loadavg)"
mem_sampler
trap 'rm -f "$OUT/.mem.on"' EXIT
PREV=""
SEEN=" "
for st in $STATES; do
  # A state named twice ("t0 t0": the stability check) writes its files as t0-2, t0-3 ...
  K=$st; n=1; while [[ "$SEEN" == *" $K "* ]]; do n=$((n + 1)); K=$st-$n; done; SEEN="$SEEN$K "
  log "=== state $st ($K) ==="
  lab/scenario.sh "$st" 2>&1 | tail -1 | tee -a "$OUT/run.log"
  # every packet the scanner sends on the lab interface, for one-second bins (e2e/ppsbins)
  LABIF=$(docker exec "$CZ" sh -c "ip -o -4 addr | awk '/ 10\\.66\\./ {print \$2}'")
  docker rm -f "$PROJECT-tcpdump" >/dev/null 2>&1
  docker image inspect czfull-tcpdump:latest >/dev/null 2>&1 ||
    printf 'FROM alpine:3.22\nRUN apk add --no-cache tcpdump\n' | docker build -q -t czfull-tcpdump:latest - >/dev/null
  docker run -d --name "$PROJECT-tcpdump" --network "container:$CZ" --cap-add NET_RAW --cap-add NET_ADMIN \
    czfull-tcpdump:latest tcpdump -i "$LABIF" -n -tt -l "src host $LR_IP or arp" >/dev/null
  P0=$(txp)
  T0=$(date +%s)
  RUN=$(api POST /runs "{\"profile_id\":$PROFILE}" | jq -r .id)
  log "run $RUN started"
  rm -f "$OUT/.second-run"
  SECOND_PID=""
  if [ -n "${LR_SECOND:-}" ]; then
    (
      sleep "${LR_SECOND_AFTER:-60}"
      S2=$(api POST /scopes '{"name":"lab-run: second run","criticality":1}' | jq -r .id)
      api POST /scopes/$S2/targets "$(jq -nc --arg t "$LR_SECOND" '{text: $t}')" >/dev/null
      P2=$(api POST /profiles "$(echo "$PJSON" | jq -c --argjson s "$S2" '.name = (.name + " (second)") | .scope_ids = [$s]')" | jq -r .id)
      R2=$(api POST /runs "{\"profile_id\":$P2}" | jq -r .id)
      log "second run $R2 started on $LR_SECOND, $(( $(date +%s) - T0 )) s after run $RUN"
      echo "$R2" >"$OUT/.second-run"
    ) &
    SECOND_PID=$!
  fi
  PEAK=0; LP=$P0; LT=$(date +%s)
  while :; do
    R=$(api GET /runs/$RUN)
    case "$(echo "$R" | jq -r .status)" in completed|failed|cancelled) break ;; esac
    sleep 3
    # peak packet rate on the lab interface, over windows of about 3 s
    NP=$(txp); NT=$(date +%s)
    if [ "$NT" -gt "$LT" ]; then RATE=$(( (NP - LP) / (NT - LT) )); [ "$RATE" -gt "$PEAK" ] && PEAK=$RATE; fi
    LP=$NP; LT=$NT
  done
  WALL=$(( $(date +%s) - T0 ))
  [ -n "$SECOND_PID" ] && wait "$SECOND_PID" # only the second run's starter (the memory sampler runs on)
  if [ -f "$OUT/.second-run" ]; then
    R2=$(cat "$OUT/.second-run")
    while :; do
      S2J=$(api GET /runs/$R2)
      case "$(echo "$S2J" | jq -r .status)" in completed|failed|cancelled) break ;; esac
      sleep 3
    done
    log "second run $R2 $(echo "$S2J" | jq -c '{status, started_at, finished_at, hosts_up: .stats.hosts_up, services: .stats.services_open, packets: .stats.packets_sent, peak_pps: .stats.peak_pps}')"
  fi
  P1=$(txp)
  sleep 1; docker logs "$PROJECT-tcpdump" 2>/dev/null > "$OUT/tcpdump-$K.txt"; docker rm -f "$PROJECT-tcpdump" >/dev/null 2>&1
  CAPPPS=$(echo "$PJSON" | jq '.rate.max_pps')
  go run ./e2e/ppsbins -src "$LR_IP" -cap "$CAPPPS" "$OUT/tcpdump-$K.txt" > "$OUT/pps-$K.txt"
  go run ./e2e/ppsbins -src "$LR_IP" -cap "$CAPPPS" -json "$OUT/tcpdump-$K.txt" > "$OUT/pps-$K.json"
  # A gap of 5 s or more with no packet from the scanner, followed by a burst
  # over the cap, is a frozen VM (overloaded host: nmap sends its backlog);
  # a gap without a burst is an idle scanner (run start: DNS and planning).
  GAP=$(awk -v ip="$LR_IP" '$3 ~ "^"ip"\\." {t=$1; if (p && t-p > g) {g=t-p; at=p; nx=t}; p=t} END {printf "%.1f %d %d", g, at, nx}' "$OUT/tcpdump-$K.txt")
  read -r GAPS GAPAT GAPNX <<< "$GAP"
  AFTER=$(awk -v ip="$LR_IP" -v s="$GAPNX" '$3 ~ "^"ip"\\." && int($1) >= s && int($1) < s + 3 {n[int($1)]++} END {m=0; for (k in n) if (n[k] > m) m = n[k]; print m}' "$OUT/tcpdump-$K.txt")
  VERDICT=$(awk -v g="$GAPS" -v a="$AFTER" -v c="$CAPPPS" 'BEGIN { if (g < 5) print "ok"; else if (a > c * 1.1) print "INVALID for the wire measurement: a gap of 5 s or more followed by a burst over the cap (VM freeze); rerun"; else print "a gap of 5 s or more without a burst after it (idle scanner, not a freeze)" }')
  log "tcpdump: longest gap without scanner packets $GAPS s (at $(date -r "$GAPAT" +%H:%M:%S 2>/dev/null || echo "$GAPAT")), max $AFTER packets per second in the 3 s after it: $VERDICT"
  # wall time of the general pass and of the deep pass (product log)
  docker logs "$CZ" 2>&1 | jq -Rc --argjson r "$RUN" 'fromjson? | select(.run? == $r and (.msg == "scan plan ready" or .msg == "deep pass" or .msg == "deep pass finished" or .msg == "run finished"))' > "$OUT/passlog-$K.jsonl" 2>/dev/null
  PT=$(jq -rs 'map({(.msg): .}) | add // {} | . as $m | def t(k): ($m[k].time // empty) | sub("\\.[0-9]+Z$"; "Z") | fromdate;
      ([t("deep pass")] + [t("run finished")])[0] as $gEnd | (t("scan plan ready")) as $s | ([t("deep pass finished")][0] // null) as $dEnd |
      "\(($gEnd - $s) | floor) \(if $dEnd then (($dEnd - t("deep pass")) | floor) else "-" end) \($m["deep pass"].hosts // "-") \($m["deep pass"].waiting // "-") \($m["deep pass finished"].new_open // "-")"' "$OUT/passlog-$K.jsonl" 2>/dev/null)
  # the kernel packet cap (internal/kcap): active, its rate and the packets it dropped so far
  api GET /settings/safety | jq -c '.kernel_cap // null' > "$OUT/kcap-$K.json" 2>/dev/null
  log "kernel cap: $(cat "$OUT/kcap-$K.json")"
  if [ -n "$PT" ]; then
    echo "$PT" > "$OUT/passtimes-$K.txt"
    read -r PG PD PH PW PN <<< "$PT"
    log "pass wall times: general $PG s, deep $PD s (deep pass: $PH hosts, $PW waiting, $PN new open services)"
  fi
  gzip -f "$OUT/tcpdump-$K.txt"
  sed -n 2,3p "$OUT/pps-$K.txt" | tee -a "$OUT/run.log"
  echo "$R" | jq . > "$OUT/run-$K.json"
  log "run $RUN $(echo "$R" | jq -r .status) in $WALL s; tx packets on the lab interface: $((P1 - P0)), peak $PEAK pps; $(echo "$R" | jq -c '{hosts_up: .stats.hosts_up, services: .stats.services_open, packets: .stats.packets_sent, avg_pps: (.stats.avg_pps|floor), peak_pps: .stats.peak_pps, http_requests: .stats.http_requests, elapsed: .stats.elapsed_sec}')"
  echo "$K run=$RUN wall=$WALL tx=$((P1 - P0)) peak=$PEAK" >> "$OUT/runs.txt"
  e2e/neigh-check.sh -json > "$OUT/neigh-$K.json"; log "after $K: $(e2e/neigh-check.sh)"
  curl -sS -b "$JAR" -o "$OUT/export-$K.json" "$API/export/runs/$RUN.json"
  api GET "/changes?run_id=$RUN&limit=1000" > "$OUT/changes-$K.json"
  go run ./e2e/score -truth lab/ground-truth/$st.json -export "$OUT/export-$K.json" -ignore "$IGNORE" -max-list 0 > "$OUT/score-$K.txt"
  go run ./e2e/score -truth lab/ground-truth/$st.json -export "$OUT/export-$K.json" -ignore "$IGNORE" -json > "$OUT/score-$K.json"
  go run ./e2e/score -truth lab/ground-truth/$st.json -export "$OUT/export-$K.json" -ignore "$IGNORE" -strict -json > "$OUT/score-strict-$K.json"
  sed -n '1,12p' "$OUT/score-$K.txt" | tee -a "$OUT/run.log"
  if [ -n "$PREV" ] && [ "$K" = "$st" ] && [ -f "lab/ground-truth/changes-$PREV-$st.json" ]; then
    go run ./e2e/score -changes lab/ground-truth/changes-$PREV-$st.json -truth-from lab/ground-truth/$PREV.json -truth lab/ground-truth/$st.json \
      -from "$OUT/export-$PREV.json" -to "$OUT/export-$K.json" -ignore "$IGNORE" -max-list 0 > "$OUT/changes-score-$PREV-$st.txt"
    go run ./e2e/score -changes lab/ground-truth/changes-$PREV-$st.json -truth-from lab/ground-truth/$PREV.json -truth lab/ground-truth/$st.json \
      -from "$OUT/export-$PREV.json" -to "$OUT/export-$K.json" -product-changes "$OUT/changes-$K.json" -ignore "$IGNORE" -max-list 0 > "$OUT/product-changes-score-$PREV-$st.txt"
    log "changes $PREV -> $st (export diff):     $(sed -n 4p "$OUT/changes-score-$PREV-$st.txt")"
    log "changes $PREV -> $st (product changes): $(sed -n 4p "$OUT/product-changes-score-$PREV-$st.txt")"
  fi
  PREV=$st
done
rm -f "$OUT/.mem.on"; sleep 2
log "memory of the Czujka container: max $(mem_max) MiB ($(wc -l < "$OUT/mem.txt" | tr -d ' ') samples)"
log "database size: $(docker exec $PROJECT-db-1 psql -U czujka -d czujka -tAc "select pg_size_pretty(pg_database_size('czujka'))")"
log "load average at the end: $(sysctl -n vm.loadavg 2>/dev/null || cut -d' ' -f1-3 /proc/loadavg)"
FINAL=${LR_FINAL_STATE-t0}
if [ -n "$FINAL" ]; then lab/scenario.sh "$FINAL" 2>&1 | tail -1 | tee -a "$OUT/run.log"; fi
if [ "${LR_KEEP:-0}" != 1 ]; then $DC down -v --remove-orphans >/dev/null 2>&1; log "product stopped (LR_KEEP=1 keeps it)"; fi
log "output: $OUT"
