#!/usr/bin/env bash
# Measures Czujka on the scale lab through its REST API.
#
#   lab/scale/measure.sh setup                  login, scope 10.77.0.0/16, profile = the seeded default profile + that scope
#   lab/scale/measure.sh run NAME [MAXPPS [HTTPRPS]]
#                                               one run: wall time, phases, packets per second on the wire, memory,
#                                               database size, export JSON, changes; MAXPPS raises the profile and policy cap,
#                                               HTTPRPS sets the profile http_rps (at most the policy max_http_rps, 50 by default)
#   lab/scale/measure.sh api RUN NAME           time of the list endpoints, exports and reports for run RUN
#
# The safety policy stays the product default (1000 pps) unless MAXPPS is given.
# Output: $CZS_OUT (default ~/czscale/out). Product: lab/scale/compose.yml on 127.0.0.1:$CZS_PORT.
set -uo pipefail
PORT=${CZS_PORT:-18640}
OUT=${CZS_OUT:-$HOME/czscale/out}
API=http://127.0.0.1:$PORT/api/v1
CZ=czscale-czujka-1
DB=czscale-db-1
JAR=$OUT/.jar
mkdir -p "$OUT"
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/run.log"; }
login() {
  local l; l=$(curl -sS -c "$JAR" -H "Content-Type: application/json" -d "{\"email\":\"admin@czujka.local\",\"password\":\"$CZS_ADMIN_PASSWORD\"}" $API/auth/login)
  CSRF=$(echo "$l" | jq -r .csrf_token); [ -n "$CSRF" ] && [ "$CSRF" != null ] || { echo "login failed: $l"; exit 1; }
}
api() {
  local out code
  if [ $# -ge 3 ]; then out=$(curl -sS -b "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" -d "$3" -w "\n%{http_code}" "$API$2")
  else out=$(curl -sS -b "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" -w "\n%{http_code}" "$API$2"); fi
  code=${out##*$'\n'}
  if [ "$code" -ge 400 ]; then echo "HTTP $code for $1 $2: ${out%$'\n'*}" >&2; return 1; fi
  printf "%s" "${out%$'\n'*}"
}
ifname() { docker exec "$CZ" sh -c "ip -o -4 addr | grep ' 10.78.0.2/' | awk '{print \$2}'"; }
login

case "${1:-}" in
setup)
  SCOPE=$(api POST /scopes '{"name":"Skala (lab/scale)","description":"10.77.0.0/16: farmy laboratorium skali","criticality":3}' | jq -r .id)
  api POST /scopes/$SCOPE/targets '{"text":"10.77.0.0/16"}' | jq -c '{saved: (.valid | length), address_count, excluded}' | tee -a "$OUT/run.log"
  DEF=$(api GET "/profiles?limit=100" | jq -c '[(.items // .)[] | select(.name | startswith("Domyślny"))][0]')
  PJSON=$(echo "$DEF" | jq -c --argjson s "$SCOPE" 'del(.id, .created_at, .updated_at, .next_run_at, .last_run_id) | .name = "Skala: profil domyślny" | .scope_ids = [$s] | .schedule.enabled = false')
  echo "$PJSON" | jq . > "$OUT/profile.json"
  PROFILE=$(api POST /profiles "$PJSON" | jq -r .id)
  echo "$PROFILE" > "$OUT/.profile"
  api GET /settings/safety | jq . > "$OUT/policy.json"
  log "scope $SCOPE, profile $PROFILE: $(echo "$PJSON" | jq -c '{ports, rate, udp: .udp.enabled, version_intensity}')"
  api POST /profiles/$PROFILE/estimate | jq -c . | tee -a "$OUT/run.log" ;;
run)
  NAME=${2:?name}; WANT=${3:-}; HRPS=${4:-}
  PROFILE=$(cat "$OUT/.profile")
  if [ -n "$WANT" ]; then
    POL=$(api GET /settings/safety | jq -c --argjson w "$WANT" '.max_pps = ([.max_pps, $w] | max)')
    api PUT /settings/safety "$POL" | jq -c '{max_pps}' | tee -a "$OUT/run.log"
    P=$(api GET /profiles/$PROFILE | jq -c --argjson w "$WANT" '{rate: (.rate | .max_pps = $w)}')
    api PATCH /profiles/$PROFILE "$P" | jq -c '{rate}' | tee -a "$OUT/run.log" || { log "the profile cap could not be raised"; exit 1; }
  fi
  if [ -n "$HRPS" ]; then
    P=$(api GET /profiles/$PROFILE | jq -c --argjson h "$HRPS" '{rate: (.rate | .http_rps = $h)}')
    api PATCH /profiles/$PROFILE "$P" | jq -c '{rate}' | tee -a "$OUT/run.log" || { log "http_rps could not be set"; exit 1; }
  fi
  IF=$(ifname)
  docker rm -f czscale-tcpdump >/dev/null 2>&1
  # packets the scanner sends on the farm interface, counted per second inside the capture container (no capture file)
  docker run -d --name czscale-tcpdump --network "container:$CZ" --cap-add NET_RAW --cap-add NET_ADMIN --entrypoint sh czscale-tcpdump:1 -c \
    "tcpdump -i $IF -n -tt -l 'src host 10.78.0.2' 2>/dev/null | awk '{s=int(\$1); if (s!=c && c) {print c, n; fflush(); n=0} c=s; n++} END {print c, n}'" >/dev/null
  : > "$OUT/mem-$NAME.txt"
  ( while [ ! -f "$OUT/.stop-$NAME" ]; do echo "$(date +%s) $(docker stats --no-stream --format '{{.MemUsage}}' $CZ | awk '{print $1}') $(docker stats --no-stream --format '{{.MemUsage}}' $DB | awk '{print $1}')" >> "$OUT/mem-$NAME.txt"; sleep 2; done ) &
  rm -f "$OUT/.stop-$NAME"
  P0=$(docker exec "$CZ" cat /sys/class/net/$IF/statistics/tx_packets)
  T0=$(date +%s)
  RUN=$(api POST /runs "{\"profile_id\":$PROFILE}" | jq -r .id)
  log "$NAME: run $RUN started"
  LAST=; TA=; while :; do
    sleep 2
    R=$(api GET /runs/$RUN) || { login; continue; }
    S=$(echo "$R" | jq -r .status)
    if [ "$S" != "$LAST" ]; then log "$NAME: run $RUN status $S at +$(( $(date +%s) - T0 )) s"; LAST=$S; [ "$S" = analyzing ] && TA=$(date +%s); fi
    case "$S" in completed|failed|cancelled) break ;; esac
  done
  T1=$(date +%s)
  P1=$(docker exec "$CZ" cat /sys/class/net/$IF/statistics/tx_packets)
  touch "$OUT/.stop-$NAME"; sleep 3
  docker logs czscale-tcpdump > "$OUT/pps-$NAME.txt" 2>/dev/null; docker rm -f czscale-tcpdump >/dev/null
  echo "$R" | jq . > "$OUT/run-$NAME.json"
  PEAK=$(sort -k2 -n "$OUT/pps-$NAME.txt" | tail -1 | awk '{print $2}')
  OVER=$(awk -v c="${WANT:-1000}" '$2 > c' "$OUT/pps-$NAME.txt" | wc -l)
  MEM=$(awk '{v=$2; u=v; gsub(/[0-9.]/,"",u); gsub(/[^0-9.]/,"",v); if(u=="GiB")v*=1024; if(u=="KiB")v/=1024; v+=0; if(v>m)m=v} END{printf "%.0f", m}' "$OUT/mem-$NAME.txt")
  MEMDB=$(awk '{v=$3; u=v; gsub(/[0-9.]/,"",u); gsub(/[^0-9.]/,"",v); if(u=="GiB")v*=1024; if(u=="KiB")v/=1024; v+=0; if(v>m)m=v} END{printf "%.0f", m}' "$OUT/mem-$NAME.txt")
  DBSIZE=$(docker exec $DB psql -U czujka -d czujka -tAc "select pg_database_size('czujka')")
  NCH=$(api GET "/changes?run_id=$RUN&limit=1" | jq .total)
  api GET "/changes?run_id=$RUN&limit=1000" > "$OUT/changes-$NAME.json"
  ANALYSIS=$(( T1 - ${TA:-$T1} ))
  log "$NAME: run $RUN $(echo "$R" | jq -r .status) in $((T1 - T0)) s (analysis about $ANALYSIS s); wire: $((P1 - P0)) packets, peak $PEAK pps, $OVER s over the cap; czujka max $MEM MiB, db max $MEMDB MiB; db $((DBSIZE / 1048576)) MiB; changes $NCH; $(echo "$R" | jq -c '{hosts_up: .stats.hosts_up, services: .stats.services_open, http: .stats.http_services, packets: .stats.packets_sent, peak_pps: .stats.peak_pps, avg_pps: (.stats.avg_pps|floor), elapsed: .stats.elapsed_sec, passes: .stats.passes}')"
  printf '{"name":"%s","run":%s,"wall_s":%s,"analysis_s":%s,"wire_packets":%s,"wire_peak_pps":%s,"wire_seconds_over_cap":%s,"czujka_mem_max_mib":%s,"db_mem_max_mib":%s,"db_bytes":%s,"changes":%s}\n' \
    "$NAME" "$RUN" $((T1 - T0)) "$ANALYSIS" $((P1 - P0)) "${PEAK:-0}" "$OVER" "$MEM" "$MEMDB" "$DBSIZE" "$NCH" >> "$OUT/runs.jsonl"
  S0=$(date +%s.%N); curl -sS -b "$JAR" -o "$OUT/export-$NAME.json" "$API/export/runs/$RUN.json"; S1=$(date +%s.%N)
  log "$NAME: export JSON $(stat -c %s "$OUT/export-$NAME.json") bytes in $(echo "$S1 - $S0" | bc) s" ;;
api)
  RUN=${2:?run}; NAME=${3:?name}
  F=$OUT/api-$NAME.txt; : > "$F"
  t() { # label path
    local r; r=$(curl -sS -b "$JAR" -o /tmp/czs.body -w "%{http_code} %{time_total} %{size_download}" "$API$2")
    printf "%-44s %s\n" "$1" "$r" | tee -a "$F"
  }
  NH=$(api GET "/hosts?limit=1" | jq .total); NS=$(api GET "/services?limit=1" | jq .total); NC=$(api GET "/changes?limit=1" | jq .total)
  echo "hosts $NH services $NS changes $NC" | tee -a "$F"
  for rep in 1 2; do
    t "hosts first page" "/hosts?limit=50"
    t "hosts deep page" "/hosts?limit=50&offset=$((NH - 60))"
    t "services first page" "/services?limit=50"
    t "services deep page" "/services?limit=50&offset=$((NS - 60))"
    t "services of the run, first page" "/services?run_id=$RUN&limit=50"
    t "services of the run, deep page" "/services?run_id=$RUN&limit=50&offset=$((NS - 60))"
    t "changes first page" "/changes?limit=50"
    t "changes deep page" "/changes?limit=50&offset=$(( NC > 60 ? NC - 60 : 0 ))"
    t "changes of the run" "/changes?run_id=$RUN&limit=50"
    t "findings first page" "/findings?limit=50"
    t "dashboard" "/dashboard"
    t "timeline" "/timeline"
    t "timeline at run" "/timeline/at?run_id=$RUN"
    t "timeline at run, hosts deep page" "/timeline/at/hosts?run_id=$RUN&limit=50&offset=$((NH - 60))"
    t "timeline at run, services deep page" "/timeline/at/services?run_id=$RUN&limit=50&offset=$((NS - 60))"
    t "search q=nginx" "/services?q=nginx&limit=50"
    t "run" "/runs/$RUN"
    t "run hosts" "/runs/$RUN/hosts?limit=50"
  done
  for fmt in json csv xml; do t "export run $fmt" "/export/runs/$RUN.$fmt"; done
  t "export services csv" "/export/services.csv"
  t "export hosts json" "/export/hosts.json"
  t "report html" "/runs/$RUN/report.html"
  t "report md" "/runs/$RUN/report.md" ;;
*) sed -n 2,12p "$0"; exit 2 ;;
esac
