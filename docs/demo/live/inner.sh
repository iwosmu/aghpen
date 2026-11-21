#!/usr/bin/env bash
# Runs inside the live jury machine; docs/demo/live/live.sh calls it. Uses only GET/HEAD scans of the machine itself.
set -uo pipefail
. /work/.live
API=http://127.0.0.1:18080/api/v1
J=/work/lab/jury
E=/work/e2e/jury
JAR=/tmp/live.jar
UIURL=${LIVE_UI:-http://127.0.0.1:18730}
TEMPLATE_PORTS=21,80,81,443,2223,3001,5673,6379,8080,8081,8085,8086,8088,8089,8090,8474,8787,8888,15432,15673,21000-21010
log() { echo "[$(date +%H:%M:%S)] $*"; }
say() { printf '\n  %s\n' "$*"; }

login() {
  CSRF=$(curl -sS -c "$JAR" -H 'Content-Type: application/json' -d "$(jq -nc --arg p "$PW" '{email:"admin@czujka.local",password:$p}')" "$API/auth/login" | jq -r .csrf_token)
  [ -n "$CSRF" ] && [ "$CSRF" != null ] || { echo "login failed"; exit 1; }
}
api() { # method path [json]
  if [ $# -ge 3 ]; then curl -sS -b "$JAR" -c "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -d "$3" "$API$2"
  else curl -sS -b "$JAR" -c "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" "$API$2"; fi
}

czujka_up() {
  ( cd /work && CZUJKA_VERSION=$TAG CZUJKA_BIND=0.0.0.0 CZUJKA_PORT=18080 CZUJKA_ADMIN_PASSWORD="$PW" CZUJKA_ALLOWED_NETWORKS="$GW/32,$HIP/32" \
      docker compose -p czujka -f deploy/docker-compose.yml up -d --no-build --wait >/dev/null 2>&1 ) || { echo "Czujka did not start"; return 1; }
  docker network inspect czjury-hostnet >/dev/null 2>&1 && docker network connect czjury-hostnet czujka-czujka-1 >/dev/null 2>&1
  return 0
}
stacks_down() {
  local f
  for f in $J/docker-compose-*.yml $E/compose/*.yml; do docker compose --env-file $E/env/proxy-base.env -f "$f" down -v --remove-orphans >/dev/null 2>&1; done
  docker compose -f /work/lab/defectdojo/docker-compose.yml down >/dev/null 2>&1
  docker rm -f czjury-host >/dev/null 2>&1
  return 0
}
reset() {
  stacks_down
  ( cd /work && docker compose -p czujka -f deploy/docker-compose.yml down -v >/dev/null 2>&1 )
  czujka_up
}
stack() { # name [envfile] -> up -d
  local f env=${2:-proxy-base}
  case $1 in
    modern) f=$J/docker-compose-modern.yml ;; proxy) f=$J/docker-compose-modern-proxy.yml ;;
    vulnerable) f=$J/docker-compose-vulnerable.yml ;; custom) f=$J/docker-compose-custom-network.yml ;;
  esac
  ( cd $J && docker compose --env-file $E/env/$env.env -f "$f" up -d >/dev/null 2>&1 )
}
wait_ports() { # port... : every port accepts TCP and HTTP ports answer (max 240 s)
  local p t0=$(date +%s)
  for p in "$@"; do
    until (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; do [ $(( $(date +%s) - t0 )) -gt 240 ] && { log "port $p not ready"; return 1; }; sleep 1; done
  done
}
wait_http() { # port path : until the answer is not 000/502/503
  local t0=$(date +%s) c
  while :; do c=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://127.0.0.1:$1$2"); case $c in 000|502|503) ;; *) return 0 ;; esac
    [ $(( $(date +%s) - t0 )) -gt 240 ] && return 1; sleep 2; done
}
scope() { # name target -> id
  local id; id=$(api POST /scopes "$(jq -nc --arg n "$1" '{name:$n,criticality:3,tags:[]}')" | jq -r .id)
  api POST "/scopes/$id/targets" "$(jq -nc --arg t "$2" '{text:$t}')" >/dev/null; echo "$id"
}
this_computer() { # the scope and the profile that the button "Ten komputer" creates -> sets SCOPE PROFILE
  SCOPE=$(api POST /scopes '{"name":"Ten komputer","description":"Maszyna, na której działa Czujka (localhost)","owner":"","criticality":3,"tags":[]}' | jq -r .id)
  api POST "/scopes/$SCOPE/targets" '{"text":"localhost"}' >/dev/null
  PROFILE=$(api GET '/profiles?limit=200' | jq -c '.items | sort_by(.id) | .[0]' | jq -c --argjson s "$SCOPE" \
    'del(.id,.next_run_at,.last_run_id,.created_at,.updated_at) | .name = "Ten komputer: " + .name | .scope_ids = [$s] | .schedule = (.schedule + {enabled:false,cron:"",interval_minutes:0,windows:[]})' \
    | { read -r b; api POST /profiles "$b"; } | jq -r .id)
}
profile_ports() { # name scope ports -> id: the default profile with an explicit port list
  api GET '/profiles?limit=200' | jq -c '.items | sort_by(.id) | .[0]' | jq -c --argjson s "$2" --arg n "$1" --arg p "$3" \
    'del(.id,.next_run_at,.last_run_id,.created_at,.updated_at) | .name = $n | .scope_ids = [$s] | .ports = $p | .udp = {enabled:false,ports:""} | .schedule = (.schedule + {enabled:false,cron:"",interval_minutes:0,windows:[]})' \
    | { read -r b; api POST /profiles "$b"; } | jq -r .id
}
scan() { # profile -> waits; sets RUN
  local t0=$(date +%s) st
  RUN=$(api POST /runs "{\"profile_id\":$1}" | jq -r .id)
  while :; do st=$(api GET "/runs/$RUN" | jq -r .status); case $st in completed|failed|cancelled) break ;; esac; sleep 2; done
  log "scan: run $RUN $st in $(( $(date +%s) - t0 )) s ($(api GET "/runs/$RUN" | jq -r '"\(.stats.services_open) services"'))"
}
changes() { api GET "/changes?run_id=$1&limit=50" | jq -r '.items[] | "    \(.kind): \(.summary)"'; }
ready() { log "READY in $(( $(date +%s) - T0 )) s. Open $UIURL, log in as admin@czujka.local (password: live.sh pass)."; }
T0=$(date +%s)

run() { # profile-name-prefix: start a scan as the button does, wait, print its changes (fallback for the presenter)
  login; local p; p=$(api GET '/profiles?limit=200' | jq -r --arg n "$1" '[.items[] | select(.name | startswith($n))][0].id // empty')
  [ -n "$p" ] || { echo "no profile starting with: $1"; return 1; }
  scan "$p"; changes "$RUN"
}
changes_after() { # run-id: changes of every later run (re-probes included), with the run's trigger and end time
  login; local r
  for r in $(api GET "/runs?limit=50" | jq -r --argjson n "$1" '.items[] | select(.id > $n) | .id' | sort -n); do
    api GET "/runs/$r" | jq -r '"  run \(.id) (\(.trigger)), finished \(.finished_at // "-")"'; changes "$r"
  done
}

c1() { # the organisers' quickstart on the default profile ("Ten komputer")
  case ${1:-prep} in
  prep) reset; login
    ( cd $J && bash quickstart.sh up >/dev/null 2>&1 ); wait_ports 2223 3001 5673 8787 15673; wait_http 15673 /
    this_computer; scan "$PROFILE"; ready
    say "Next: live.sh 1 change, then 'Uruchom skan' on the profile 'Ten komputer: ...' (about 100 s)" ;;
  change) ( cd $J && bash quickstart.sh change >/dev/null 2>&1 ); log "quickstart change: 8787 stopped. Start the scan now." ;;
  up) ( cd $J && bash quickstart.sh up >/dev/null 2>&1 ); wait_ports 8787; log "quickstart up: 8787 is back. Start the scan now." ;;
  esac
}
c2() { # a host stops answering
  case ${1:-prep} in
  prep) reset
    docker network create --subnet 172.31.250.0/24 czjury-hostnet >/dev/null 2>&1 || true
    docker run -d --name czjury-host --network czjury-hostnet --ip "$HIP" nginx:alpine >/dev/null
    docker network connect czjury-hostnet czujka-czujka-1 >/dev/null 2>&1 || true
    login; S=$(scope "Serwer w pracowni" "$HIP"); P=$(profile_ports "Serwer w pracowni: port 80" "$S" 80)
    scan "$P"; ready; say "Next: live.sh 2 stop, then 'Uruchom skan' on 'Serwer w pracowni: port 80' (6 s); then wait about 100 s without a click" ;;
  stop) docker stop czjury-host >/dev/null; log "the host $HIP is off. Start the scan now." ;;
  start) docker start czjury-host >/dev/null; log "the host $HIP is on again." ;;
  esac
}
c3() { # latency through Toxiproxy
  case ${1:-prep} in
  prep) reset; stack proxy proxy-base; wait_ports 8085 8086 8474; wait_http 8085 /wp-admin/install.php
    login; S=$(scope "Ten komputer" localhost); P=$(profile_ports "WordPress za proxy" "$S" 8085,8086,8474)
    scan "$P"; scan "$P"; ready; say "Next: live.sh 3 slow, then 'Uruchom skan' on 'WordPress za proxy' (about 20 s)" ;;
  slow) stack proxy proxy-latency; sleep 3; wait_http 8085 /wp-admin/install.php; log "Toxiproxy adds 500 ms to 8085. Start the scan now." ;;
  fast) stack proxy proxy-base; sleep 3; wait_http 8085 /wp-admin/install.php; log "no toxic on 8085. Start the scan now." ;;
  esac
}
c4() { # a new exposure and its rules
  case ${1:-prep} in
  prep) reset; stack modern; wait_ports 80 81 443 8080 8081 6379; wait_http 8080 /wp-admin/install.php
    login; S=$(scope "Ten komputer" localhost); P=$(profile_ports "Porty szablonu" "$S" "$TEMPLATE_PORTS")
    scan "$P"; ready; say "Next: live.sh 4 expose, then 'Uruchom skan' on 'Porty szablonu' (about 50 s)" ;;
  expose) stack vulnerable; stack proxy proxy-base; wait_ports 21 8088 8089 8090 8085 8086 8474; wait_http 8088 / ; wait_http 8085 /wp-admin/install.php
    log "vulnerable and modern-proxy are up beside modern. Start the scan now." ;;
  esac
}
c5() { # roles
  case ${1:-prep} in
  prep) reset; ( cd $J && bash quickstart.sh up >/dev/null 2>&1 ); wait_ports 2223 3001 5673 8787 15673
    login; S=$(scope "Ten komputer" localhost); P=$(profile_ports "Quickstart" "$S" 2223,3001,5673,8787,15673); scan "$P"
    c5 accounts; ready ;;
  accounts) login
    echo; echo "  Accounts (passwords shown only now):"
    local slug email pw rid
    for slug in viewer analyst editor admin; do
      rid=$(api GET /roles | jq -r --arg s "$slug" '.[] | select(.slug == $s) | .id')
      email="$slug@czujka.local"; [ "$slug" = admin ] && email="admin2@czujka.local"
      pw="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 14)-Cz1"
      api POST /users "$(jq -nc --arg e "$email" --arg n "$slug" --arg p "$pw" --argjson r "$rid" '{email:$e,name:$n,password:$p,role_id:$r}')" >/dev/null
      printf '    %-22s %-10s %s\n' "$email" "$slug" "$pw"
    done ;;
  esac
}
c6() { # a signature from a real service
  case ${1:-prep} in
  prep) reset; stack custom; wait_ports 8888 15432 5673 15673 3001 2223 8787; wait_http 8888 /; wait_http 15673 /
    login; S=$(scope "Ten komputer" localhost); P=$(profile_ports "Custom network" "$S" 2223,3001,5673,8787,8888,15432,15673); scan "$P"
    ready; say "Next: Usługi -> a service -> 'Zaproponuj sygnaturę' -> Sprawdź -> Retro-hunt -> Zapisz (no scan)" ;;
  esac
}
c7() { # import, edit, a second scan keeps the edit
  case ${1:-prep} in
  prep) reset; ( cd $J && bash quickstart.sh up >/dev/null 2>&1 ); wait_ports 2223 3001 5673 8787 15673
    login; S=$(scope "Ten komputer" localhost); P=$(profile_ports "Quickstart" "$S" 2223,3001,5673,8787,15673); scan "$P"
    ready; say "Files to import: docs/demo/live/samples/ (on this laptop)"; say "Next: Import -> results file, findings file; edit a finding; 'Uruchom skan' on 'Quickstart'" ;;
  esac
}
full() { # every stack at once (their ports do not overlap), two scans with a change between them, imports, role accounts
  reset; stack custom; stack modern; stack proxy proxy-base; stack vulnerable
  wait_ports $(echo "$TEMPLATE_PORTS" | tr ',' ' ' | sed 's/21000-21010//'); wait_http 8080 /wp-admin/install.php; wait_http 8085 /wp-admin/install.php; wait_http 15673 /
  login; S=$(scope "Ten komputer" localhost); P=$(profile_ports "Porty szablonu" "$S" "$TEMPLATE_PORTS"); scan "$P"
  ( cd $J && bash quickstart.sh change >/dev/null 2>&1 ); scan "$P"; changes "$RUN"
  curl -s -b "$JAR" -H "X-CSRF-Token: $CSRF" -F file=@/work/docs/demo/live/samples/wyniki-nmap.xml "$API/import/results" | jq -c '{import_run: .run_id, hosts, services}'
  curl -s -b "$JAR" -H "X-CSRF-Token: $CSRF" -F file=@/work/docs/demo/live/samples/znaleziska-dojo-generic.json "$API/import/findings" | jq -c '{findings, created}'
  c5 accounts
  ready
}
"$@"
