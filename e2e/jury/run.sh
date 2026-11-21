#!/usr/bin/env bash
# Checks Czujka on the organisers' test template (lab/jury) end to end, through the REST API only:
# for each stack it starts the stack, waits until every service answers, scans it with Czujka, compares the result
# with the truth table (e2e/jury/truth.tsv), runs the change scenarios and stops the stack. Prints a PASS/FAIL table.
#
#   CZ_URL=http://127.0.0.1:8080 CZ_PASSWORD=... e2e/jury/run.sh          (whole run, about 25 minutes)
#   e2e/jury/dind.sh                                                      (the same inside a fresh docker:dind "jury machine")
#
# It needs a running Czujka that reaches the docker host where the template publishes its ports (JURY_TARGET, default
# host.docker.internal), bash, curl, jq and docker compose. Only one template stack runs at a time (fixed host ports).
# Safety: the scan profile and the stack's safety policy (allowed_ports) hold only the template ports below; the scan
# never covers a port range of the target. Never point JURY_TARGET at a machine with other services (for example a
# developer laptop): use dind.sh, where the docker host is a throwaway container.
# Rows with an owner in truth.tsv are known gaps (GAP, not FAIL); the exit code counts FAIL only.
set -uo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD; J=$ROOT/lab/jury; E=$ROOT/e2e/jury
CZ_URL=${CZ_URL:-http://127.0.0.1:8080}; API=$CZ_URL/api/v1
EMAIL=${CZ_EMAIL:-admin@czujka.local}; PW=${CZ_PASSWORD:?set CZ_PASSWORD}
TARGET=${JURY_TARGET:-host.docker.internal}
# JURY_GUARD=1 (default) sets the safety policy's allowed_ports to the template ports: a hard guard for any docker host.
# dind.sh sets 0: there the operator lock (CZUJKA_ALLOWED_NETWORKS) confines every scan to the throwaway jury machine,
# and the juror flow (the default profile) must scan its real port list.
GUARD=${JURY_GUARD:-1}
# The default profile ("Ten komputer" copies it) must cover every template port: a miss is a FAIL.
PORTS=21,80,81,443,2223,3001,5673,6379,8080,8081,8085,8086,8088,8089,8090,8474,8787,8888,15432,15673,21000-21010
ONLY=${JURY_ONLY:-quickstart custom-network modern version vulnerable proxy}
JAR=$(mktemp); CSRF=
PASSES=0; FAILS=0; GAPS=0; CLOSED=0
TABLE=()
JUROR=()
ts() { date +%H:%M:%S; }
log() { echo "[$(ts)] $*"; }
api() { # method path [json]
  if [ $# -ge 3 ]; then curl -sS -b "$JAR" -c "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" -d "$3" "$API$2"
  else curl -sS -b "$JAR" -c "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" "$API$2"; fi
}
row() { # stack port check value owner ok detail
  local st=$1 port=$2 ck=$3 val=$4 owner=$5 ok=$6 det=$7 res
  if [ "$ok" = 1 ]; then
    if [ -n "$owner" ]; then res="PASS (gap closed: $owner)"; CLOSED=$((CLOSED + 1)); else res=PASS; PASSES=$((PASSES + 1)); fi
  else
    if [ -n "$owner" ]; then res="GAP ($owner)"; GAPS=$((GAPS + 1)); else res=FAIL; FAILS=$((FAILS + 1)); fi
  fi
  printf '  %-26s %-15s %-6s %-8s %-48s %s\n' "$res" "$st" "$port" "$ck" "$val" "$det"
  TABLE+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s' "$res" "$st" "$port" "$ck" "$val" "$det")")
}

# ---------- compose ----------
file_of() { case $1 in modern) echo docker-compose-modern.yml ;; proxy) echo docker-compose-modern-proxy.yml ;;
  vulnerable) echo docker-compose-vulnerable.yml ;; custom-network) echo docker-compose-custom-network.yml ;; esac; }
compose() { # stack [env] -- args...
  local st=$1 envf=$E/env/proxy-base.env; shift
  if [ "${1:-}" != "--" ]; then envf=$E/env/$1.env; shift; fi; shift
  # mysql:5.7, DVWA, vsftpd and wordpress:4.7 have amd64 images only. On an arm64 host pull them first with
  # --platform linux/amd64 (dind.sh copies them in); compose then runs the local image under emulation.
  ( cd "$J" && docker compose --env-file "$envf" -f "$(file_of "$st")" "$@" )
}
all_down() { for s in modern proxy vulnerable custom-network; do compose $s -- down -v --remove-orphans >/dev/null 2>&1; done
  ( cd "$J" && docker compose -f "$E/compose/docker-compose-modern-redis6.yml" down -v --remove-orphans >/dev/null 2>&1 ); }
http_ok() { local c; c=$(curl -s -m 4 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1"); case $c in 2*|3*) return 0 ;; esac; return 1; }
tcp_ok() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
wait_ready() { # label "http:port/path ..." "tcp:port ..."
  local label=$1 t0 ok
  t0=$(date +%s)
  while :; do
    ok=1
    for h in $2; do http_ok "$h" || { ok=0; break; }; done
    [ $ok = 1 ] && for p in $3; do tcp_ok "$p" || { ok=0; break; }; done
    [ $ok = 1 ] && { log "$label: every service answers after $(( $(date +%s) - t0 )) s"; return 0; }
    [ $(( $(date +%s) - t0 )) -gt 420 ] && { log "$label: services not ready after 420 s"; return 1; }
    sleep 3
  done
}
READY_modern=("80/ 81/ 8080/wp-admin/install.php 8081/" "6379 443")
READY_proxy=("8085/wp-admin/install.php 8086/dashboard/ 8474/version" "")
READY_vulnerable=("8088/wp-admin/install.php 8089/ 8090/login.php" "21 21000 21010")
READY_custom=("8888/ 3001/ 15673/ 8787/" "15432 5673 2223")
READY_quick=("3001/ 15673/ 8787/" "5673 2223")

# ---------- Czujka ----------
setup() {
  CSRF=$(curl -sS -c "$JAR" -H "Content-Type: application/json" -d "$(jq -nc --arg e "$EMAIL" --arg p "$PW" '{email:$e,password:$p}')" "$API/auth/login" | jq -r .csrf_token)
  [ -n "$CSRF" ] && [ "$CSRF" != null ] || { echo "login failed at $API"; exit 2; }
  if [ "$GUARD" = 1 ]; then
    api GET /settings/safety | jq -c --arg p "$PORTS" '.allowed_ports = $p' > "$JAR.pol"
    api PUT /settings/safety "$(cat "$JAR.pol")" | jq -c '{allowed_ports, max_pps, operator_networks}'
  else
    api GET /settings/safety | jq -c '{allowed_ports, max_pps, operator_networks}'
  fi
  SCOPE=$(api GET "/scopes?limit=100" | jq -r '[.items[] | select(.name == "Szablon jury (e2e)")][0].id // empty')
  if [ -z "$SCOPE" ]; then
    SCOPE=$(api POST /scopes '{"name":"Szablon jury (e2e)","criticality":3}' | jq -r .id)
    api POST "/scopes/$SCOPE/targets" "$(jq -nc --arg t "$TARGET" '{text:$t}')" | jq -c '{valid: [.valid[].value], invalid}'
  fi
  PROF=$(api GET "/profiles?limit=100" | jq -r '[.items[] | select(.name == "Szablon jury (e2e): porty szablonu")][0].id // empty')
  if [ -z "$PROF" ]; then
    PROF=$(api GET "/profiles?limit=100" | jq -c '[.items[] | select(.name | startswith("Domyślny"))][0]' | jq -c --argjson s "$SCOPE" --arg p "$PORTS" \
      'del(.id, .created_at, .updated_at, .next_run_at, .last_run_id) | .name = "Szablon jury (e2e): porty szablonu" | .scope_ids = [$s] | .ports = $p | .udp = {enabled: false, ports: ""} | .schedule.enabled = false' \
      | { read -r body; api POST /profiles "$body"; } | jq -r .id)
  fi
  DEFPROF=
  if [ "$GUARD" = 0 ]; then
    DEFPROF=$(api GET "/profiles?limit=100" | jq -r '[.items[] | select(.name == "Szablon jury (e2e): profil domyślny")][0].id // empty')
    if [ -z "$DEFPROF" ]; then
      DEFPROF=$(api GET "/profiles?limit=100" | jq -c '[.items[] | select(.name | startswith("Domyślny"))][0]' | jq -c --argjson s "$SCOPE" \
        'del(.id, .created_at, .updated_at, .next_run_at, .last_run_id) | .name = "Szablon jury (e2e): profil domyślny" | .scope_ids = [$s] | .schedule.enabled = false' \
        | { read -r body; api POST /profiles "$body"; } | jq -r .id)
    fi
  fi
  log "Czujka $CZ_URL: scope $SCOPE (target $TARGET), profile $PROF (ports $PORTS), default profile ${DEFPROF:-skipped (guard on)}"
}
scan() { # label [profile] -> sets RUN, SV, FN, CH
  local t0 st p=${2:-$PROF}
  t0=$(date +%s)
  RUN=$(api POST /runs "{\"profile_id\":$p}" | jq -r .id)
  # Time to the first service: the first "host" event with services on the run's event stream (SSE).
  local fs="$JAR.first.$RUN"; rm -f "$fs"
  ( curl -sN -b "$JAR" --max-time 7200 "$API/runs/$RUN/events" | while IFS= read -r l; do
      case $l in
        "event: host"*) h=1 ;;
        data:*) if [ "${h:-0}" = 1 ] && echo "$l" | grep -qE '"services":(\[\{|[1-9])'; then date +%s > "$fs"; break; fi; h=0 ;;
      esac
    done ) &
  local sse=$!
  while :; do st=$(api GET "/runs/$RUN" | jq -r .status); case $st in completed|failed|cancelled) break ;; esac; sleep 3; done
  RUNSECS=$(( $(date +%s) - t0 )); FIRSTSVC=
  [ -s "$fs" ] && FIRSTSVC=$(( $(cat "$fs") - t0 ))
  kill "$sse" 2>/dev/null; wait "$sse" 2>/dev/null
  local r; r=$(api GET "/runs/$RUN")
  log "$1: run $RUN $st in $RUNSECS s (first service after ${FIRSTSVC:-?} s): $(echo "$r" | jq -c '{hosts: .stats.hosts_up, services: .stats.services_open, packets: .stats.packets_sent, warnings: (.warnings // [] | length)}')"
  SV=$(api GET "/services?limit=500"); FN=$(api GET "/findings?limit=2000"); CH=$(api GET "/changes?run_id=$RUN&limit=500")
  RUNSTATUS=$st
}
svc() { echo "$SV" | jq -c --argjson p "$1" '[.items[] | select(.port == $p and .proto == "tcp")][0] // {}'; }
check_row() { # stack port check value owner
  local st=$1 port=$2 ck=$3 val=$4 owner=$5 s ok=0 det
  s=$(svc "$port")
  case $ck in
    open) [ "$(echo "$s" | jq -r '.state // ""')" = open ] && ok=1; det="state=$(echo "$s" | jq -r '.state // "none"') $(echo "$s" | jq -r '[.name, .product, .version] | map(select(. != null and . != "")) | join(" ")')" ;;
    name) [ "$(echo "$s" | jq -r '.name // ""')" = "$val" ] && ok=1; det="name=$(echo "$s" | jq -r '.name // ""')" ;;
    tech|notech)
      local n=${val%@*} v=; [[ $val == *@* ]] && v=${val#*@}
      local hit; hit=$(echo "$s" | jq --arg n "$n" --arg v "$v" '[(.technologies // [])[] | select((.name | ascii_downcase) == ($n | ascii_downcase) and ($v == "" or .version == $v))] | length')
      if [ "$ck" = tech ]; then [ "$hit" -ge 1 ] && ok=1; else [ "$hit" -eq 0 ] && ok=1; fi
      det="techs: $(echo "$s" | jq -r '[(.technologies // [])[] | .name + (if .version != "" then " " + .version else "" end)] | join(", ")')" ;;
    class) echo "$s" | jq -e --arg c "$val" '(.classes // []) | index($c)' >/dev/null && ok=1; det="classes: $(echo "$s" | jq -r '(.classes // []) | join(",")')" ;;
    sig)
      local id; id=$(echo "$s" | jq -r '.id // empty')
      local m=; [ -n "$id" ] && m=$(api GET "/services/$id" | jq -r '[(.latest.result.matches // [])[].signature] | join(",")')
      [[ ",$m," == *",$val,"* ]] && ok=1; det="matches: $m" ;;
    finding)
      local f; f=$(echo "$FN" | jq -r --argjson p "$port" --argjson r "$RUN" --arg v "$val" '[.items[] | select(.port == $p and .last_run_id == $r and (.type == $v or (.title | contains($v))))][0].title // ""')
      [ -n "$f" ] && ok=1; det="${f:-no such finding in run $RUN}" ;;
  esac
  row "$st" "$port" "$ck" "$val" "$owner" "$ok" "${det:0:110}"
}
juror() { # stack: what a juror sees with the default profile on target $TARGET
  JUROR_RUN=
  [ -n "$DEFPROF" ] || return 0
  scan "$1 with the default profile" "$DEFPROF"
  JUROR_RUN=$RUN
  local port s found=0 total=0
  for port in $(grep -v '^#' "$E/truth.tsv" | awk -F'\t' -v s="$1" '$1 == s && $3 == "open" {print $2}'); do
    s=$(svc "$port")
    total=$((total + 1))
    if [ "$(echo "$s" | jq -r '.state // ""')" = open ]; then found=$((found + 1)); row "juror:$1" "$port" open "found with the default profile" "" 1 "$(echo "$s" | jq -r '[.name, .product, .version] | map(select(. != null and . != "")) | join(" ")')"
    else row "juror:$1" "$port" open "found with the default profile" "" 0 "not in run $RUN"; fi
  done
  JUROR+=("$(printf '%s\t%s/%s\t%s\t%s\t%s' "$1" "$found" "$total" "${FIRSTSVC:-?}" "$RUNSECS" "$RUN")")
}
truth() { # stack
  # awk keeps empty columns (read with a tab IFS would merge them); \x1f is not whitespace.
  while IFS=$'\x1f' read -r st port ck val owner; do
    check_row "$st" "$port" "$ck" "$val" "$owner"
  done < <(awk -F'\t' -v s="$1" '!/^#/ && $1 == s {printf "%s\x1f%s\x1f%s\x1f%s\x1f%s\n", $1, $2, $3, $4, $5}' "$E/truth.tsv")
}
change_row() { # label port kinds-regex text-regex owner
  local c
  c=$(echo "$CH" | jq -r --argjson p "$2" --arg k "$3" --arg t "$4" '[.items[] | select(.port == $p and ((.kind | test($k)) or ($t != "" and (.summary | test($t; "i")))))][0] | if . == null then "" else "run \(.run_id) \(.kind): \(.summary)" end')
  local all; all=$(echo "$CH" | jq -r --argjson p "$2" '[.items[] | select(.port == $p) | "\(.kind)@run\(.run_id)"] | unique | join(",")')
  if [ -n "$c" ]; then row scenario "$2" change "$1" "$5" 1 "${c:0:110}"; else row scenario "$2" change "$1" "$5" 0 "changes on this port in run $RUN: ${all:-none}"; fi
}
open_row() { # label port owner
  local s; s=$(svc "$2")
  if [ "$(echo "$s" | jq -r '.state // ""')" = open ]; then row scenario "$2" open "$1" "$3" 1 "open"; else row scenario "$2" open "$1" "$3" 0 "state=$(echo "$s" | jq -r '.state // "none"')"; fi
}
rt_of() { local id; id=$(svc "$1" | jq -r '.id // empty'); [ -n "$id" ] && api GET "/services/$id" | jq -r '.latest.result.http.response_ms // empty'; }
status_of() { local id; id=$(svc "$1" | jq -r '.id // empty'); [ -n "$id" ] && api GET "/services/$id" | jq -r '.latest.result.http.status // empty'; }

# ---------- run ----------
echo "=== Czujka on the organisers' template (lab/jury), $(date '+%Y-%m-%d %H:%M %Z') ==="
echo "Czujka $(curl -s "$CZ_URL/healthz" | jq -c '{version, engine, tde}'); docker host $(uname -m); target $TARGET"
setup
all_down
want() { [[ " $ONLY " == *" $1 "* ]]; }

if want quickstart; then
  echo; echo "=== Quickstart: the service on 8787 disappears and comes back (lab/jury/quickstart.sh) ==="
  ( cd "$J" && bash quickstart.sh up >/dev/null 2>&1 ) && wait_ready quickstart "${READY_quick[0]}" "${READY_quick[1]}"
  scan "quickstart up"; for p in 2223 3001 5673 8787 15673; do open_row "quickstart: open after up" $p ""; done
  ( cd "$J" && bash quickstart.sh change >/dev/null 2>&1 ); sleep 2
  scan "quickstart change"
  change_row "quickstart: 8787 gone after change" 8787 '^service_gone$' '' ""
  for p in 2223 3001 5673 15673; do open_row "quickstart: still open after change" $p ""; done
  ( cd "$J" && bash quickstart.sh up >/dev/null 2>&1 ) && wait_ready quickstart "${READY_quick[0]}" "${READY_quick[1]}"
  scan "quickstart up again"
  open_row "quickstart: 8787 open again" 8787 ""
  change_row "quickstart: 8787 reported as back" 8787 '^service_returned$' 'wróci' ""
fi

if want custom-network; then
  echo; echo "=== custom-network: httpbin, PostgreSQL, RabbitMQ, Gitea, nginx ==="
  compose custom-network -- up -d >/dev/null 2>&1; wait_ready custom-network "${READY_custom[0]}" "${READY_custom[1]}"
  juror custom-network
  scan custom-network; truth custom-network
fi

if want modern; then
  echo; echo "=== modern: WordPress, phpMyAdmin, Redis, Nginx Proxy Manager (and the swap from custom-network) ==="
  compose custom-network -- down -v >/dev/null 2>&1
  compose modern -- up -d >/dev/null 2>&1; wait_ready modern "${READY_modern[0]}" "${READY_modern[1]}"
  juror modern
  scan modern; truth modern
  if want custom-network; then
    # The swap shows in the first scan of the stage: the default-profile scan when it ran, else the template scan.
    CH=$(api GET "/changes?limit=1000" | jq -c --argjson r "${JUROR_RUN:-$RUN}" '{items: [.items[] | select(.run_id >= $r)]}')
    change_row "swap: custom-network 8787 gone" 8787 '^service_gone$' '' ""
    change_row "swap: custom-network 3001 gone" 3001 '^service_gone$' '' ""
    change_row "swap: modern 8080 new" 8080 '^service_new$' '' ""
  fi
fi

if want version; then
  echo; echo "=== version change: modern with redis:6 instead of redis:7 (a copy under e2e/jury/compose) ==="
  # --renew-anon-volumes: redis:6 cannot read the RDB file that redis:7 left in the image's anonymous /data volume.
  ( cd "$J" && docker compose -f "$E/compose/docker-compose-modern-redis6.yml" up -d --renew-anon-volumes >/dev/null 2>&1 ); wait_ready modern-redis6 "${READY_modern[0]}" "${READY_modern[1]}"
  scan "modern with redis:6"
  change_row "version: Redis 7.4.12 -> 6.x" 6379 '^(tech_version|service_changed)$' '' ""
  check_row version 6379 tech "Redis" ""
  ( cd "$J" && docker compose -f "$E/compose/docker-compose-modern-redis6.yml" down -v >/dev/null 2>&1 )
fi

if want vulnerable; then
  echo; echo "=== vulnerable: vsftpd, WordPress 4.7, Adminer, DVWA ==="
  compose modern -- down -v >/dev/null 2>&1
  compose vulnerable -- up -d >/dev/null 2>&1; wait_ready vulnerable "${READY_vulnerable[0]}" "${READY_vulnerable[1]}"
  juror vulnerable
  scan vulnerable; truth vulnerable
  compose vulnerable -- down -v >/dev/null 2>&1
fi

if want proxy; then
  echo; echo "=== modern-proxy: WordPress behind Traefik and Toxiproxy; then the four toxics ==="
  compose proxy proxy-base -- up -d >/dev/null 2>&1; wait_ready proxy "${READY_proxy[0]}" ""
  juror proxy
  scan "proxy, no toxic"; truth proxy
  RT0=$(rt_of 8085); log "8085 response time without a toxic: ${RT0:-?} ms"
  for tox in latency timeout bandwidth slowclose; do
    compose proxy proxy-$tox -- up -d >/dev/null 2>&1
    sleep 8
    log "toxics now: $(curl -s http://127.0.0.1:8474/proxies/wordpress/toxics | jq -c '[.[] | {type, attributes}]')"
    scan "proxy, toxic $tox"
    [ "$RUNSTATUS" = completed ] && ok=1 || ok=0
    row scenario 8085 run "toxic $tox: the scan completes" "" $ok "run $RUN $RUNSTATUS"
    open_row "toxic $tox: 8085 still open" 8085 ""
    RT=$(rt_of 8085); log "8085 response time with $tox: ${RT:-?} ms (without: ${RT0:-?} ms)"
    if [ "$tox" = latency ]; then
      [ -n "$RT" ] && [ -n "$RT0" ] && [ "$RT" -ge $((RT0 + 400)) ] && ok=1 || ok=0
      row scenario 8085 rt "latency 500 ms: response time recorded" "" $ok "response_ms ${RT0:-?} -> ${RT:-?}"
      change_row "latency 500 ms: reported as slower" 8085 '^response_slower$' 'wolniej' ""
    fi
    if [ "$tox" = timeout ]; then
      # Through Traefik the timeout toxic gives HTTP 502 after about 1.5 s (curl from the docker host).
      ST=$(status_of 8085)
      { [ "${ST:-0}" -ge 500 ] || [ "${RT:-0}" -ge 1000 ] || echo "$CH" | jq -e '[.items[] | select(.port == 8085 and .kind == "response_slower")] | length > 0' >/dev/null; } && ok=1 || ok=0
      row scenario 8085 http "timeout 1 s: failing or slow answer recorded" engine $ok "http status ${ST:-none}, response_ms ${RT:-none}"
    fi
  done
  compose proxy proxy-base -- down -v >/dev/null 2>&1
fi

all_down
echo
echo "=== Summary ==="
printf '%s\n' "${TABLE[@]}" | awk -F'\t' '{print $1}' | sed 's/ (.*//' | sort | uniq -c
echo "PASS: $PASSES  FAIL: $FAILS  GAP: $GAPS  GAP CLOSED: $CLOSED"
if [ ${#JUROR[@]} -gt 0 ]; then
  echo "Default profile on target $TARGET (the juror flow), per stack:"
  printf '  %-16s %-14s %-20s %-18s %s\n' stack "template ports" "first service (s)" "run finished (s)" run
  printf '%s\n' "${JUROR[@]}" | while IFS=$'\t' read -r a b c d e; do printf '  %-16s %-14s %-20s %-18s %s\n' "$a" "$b" "$c" "$d" "$e"; done
fi
rm -f "$JAR" "$JAR.pol" "$JAR".first.*
[ "$FAILS" -eq 0 ] && echo "JURY TEMPLATE OK" || exit 1
