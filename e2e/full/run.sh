#!/usr/bin/env bash
# Full end-to-end check of Czujka: the product stack from docker compose, a
# real target network with real services, and only the REST API.
#
#   ./e2e/full/run.sh            run every check, then remove everything it created
#   E2E_KEEP=1 ./e2e/full/run.sh keep the stack and the lab for inspection
#
# It scans only the docker network it creates itself (czfull-net, 10.91.0.0/22).
# Environment: E2E_PROJECT (czfull-e2e), E2E_PORT (18492), E2E_SKIP_BUILD=1 reuses the image.
# Output: one line "PASS" or "FAIL" per check; exit code 1 when a check failed.
set -uo pipefail
cd "$(dirname "$0")/../.."
PROJECT=${E2E_PROJECT:-czfull-e2e}
PORT=${E2E_PORT:-18492}
BASE=http://127.0.0.1:$PORT
API=$BASE/api/v1
NET=czfull-net
P=10.91
ADMIN=admin@czujka.local
ADMIN_PW="Full-$(date +%s)-$RANDOM$RANDOM"
TMP=$(mktemp -d)
JAR=$TMP/jar
CSRF=
FAILS=0
PASSES=0
DC="docker compose -p $PROJECT -f deploy/docker-compose.yml -f deploy/docker-compose.scan-network.yml"
CZ=$PROJECT-czujka-1
export CZUJKA_PORT=$PORT CZUJKA_VERSION=${CZUJKA_VERSION:-czfull} CZUJKA_ADMIN_EMAIL=$ADMIN CZUJKA_ADMIN_PASSWORD=$ADMIN_PW
export CZUJKA_SCHED_INTERVAL=5s CZUJKA_SCAN_NETWORK=$NET CZUJKA_TZ=Europe/Warsaw

cleanup() {
  rm -f "$TMP/mem.on"
  if [ "${E2E_KEEP:-0}" != 1 ]; then
    docker rm -f "$PROJECT-tcpdump" >/dev/null 2>&1 || true
    $DC down -v --remove-orphans >/dev/null 2>&1 || true
    e2e/full/lab.sh down >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

step() { echo; echo "=== $* ==="; }
pass() { echo "  PASS  $1"; PASSES=$((PASSES + 1)); }
fail() { echo "  FAIL  $1"; FAILS=$((FAILS + 1)); }
check() { # description got want
  if [ "$2" = "$3" ]; then pass "$1: $2"; else fail "$1: got \"$2\", want \"$3\""; fi
}
checkge() { # description got min
  if [ "${2:-x}" -ge "$3" ] 2>/dev/null; then pass "$1: $2 (>= $3)"; else fail "$1: got \"$2\", want >= $3"; fi
}
checkle() { # description got max
  if [ "${2:-x}" -le "$3" ] 2>/dev/null; then pass "$1: $2 (<= $3)"; else fail "$1: got \"$2\", want <= $3"; fi
}
api() { # method path [json body]; prints the body; returns 1 on an HTTP error
  local out code
  if [ $# -ge 3 ]; then
    out=$(curl -sS -b "$JAR" -c "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" -d "$3" -w "\n%{http_code}" "$API$2")
  else
    out=$(curl -sS -b "$JAR" -c "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" -w "\n%{http_code}" "$API$2")
  fi
  code=${out##*$'\n'}
  if [ "$code" -ge 400 ]; then echo "HTTP $code for $1 $2: ${out%$'\n'*}" >&2; printf "%s" "${out%$'\n'*}"; return 1; fi
  printf "%s" "${out%$'\n'*}"
}
status_of() { # method path [json] -> HTTP status only
  if [ $# -ge 3 ]; then
    curl -sS -o /dev/null -b "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" -d "$3" -w "%{http_code}" "$API$2"
  else
    curl -sS -o /dev/null -b "$JAR" -X "$1" -H "X-CSRF-Token: $CSRF" -w "%{http_code}" "$API$2"
  fi
}
upload() { curl -sS -b "$JAR" -H "X-CSRF-Token: $CSRF" -F "file=@$2" "$API$1"; }
labif() { docker exec "$CZ" sh -c "ip -o -4 addr | awk '/ $P\\./ {print \$2}'"; }
txpackets() { docker exec "$CZ" cat "/sys/class/net/$LABIF/statistics/tx_packets"; }
# A tcpdump sidecar shares the network namespace of the Czujka container and records every packet
# that leaves the scan interface. The image (alpine + tcpdump) is built locally on first use.
cap_start() {
  docker image inspect czfull-tcpdump:latest >/dev/null 2>&1 ||
    printf 'FROM alpine:3.22\nRUN apk add --no-cache tcpdump\n' | docker build -q -t czfull-tcpdump:latest - >/dev/null
  docker rm -f "$PROJECT-tcpdump" >/dev/null 2>&1 || true
  docker run -d --name "$PROJECT-tcpdump" --net "container:$CZ" --cap-add NET_RAW --cap-add NET_ADMIN \
    czfull-tcpdump:latest tcpdump -i "$LABIF" -n -tt -l -Q out >/dev/null
  sleep 3
}
# cap_stop FILE: stops the capture and writes it without the API's own replies (source port 8080),
# which leave through the same interface when the default route uses it. They are not scan traffic.
cap_stop() {
  docker logs "$PROJECT-tcpdump" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+ ' | grep -v '\.8080 >' > "$1" || true
  docker rm -f "$PROJECT-tcpdump" >/dev/null 2>&1 || true
}
mem_sampler() { # samples the memory of the Czujka container every 2 s while $TMP/mem.on exists
  touch "$TMP/mem.on"
  ( while [ -f "$TMP/mem.on" ]; do docker stats --no-stream --format '{{.MemUsage}}' "$CZ" 2>/dev/null | awk '{print $1}' >> "$TMP/mem.txt"; sleep 2; done ) &
}
mem_max() { # the largest sample in MiB
  awk '{v=$1; u=v; gsub(/[0-9.]/,"",u); gsub(/[^0-9.]/,"",v); if(u=="GiB")v*=1024; if(u=="KiB")v/=1024; if(u=="B")v/=1048576; if(v>m)m=v} END{printf "%.1f", m}' "$TMP/mem.txt"
}
follow() { # run id: follows the SSE stream until the "done" event
  local id=$1 ev="" counts="" n=0 last=""
  while IFS= read -r line; do
    case "$line" in
      "event: "*) ev=${line#event: }; n=$((n + 1)); counts="$counts $ev" ;;
      "data: "*)
        if [ "$ev" = progress ]; then last=${line#data: }; fi
        if [ "$ev" = done ]; then last=${line#data: }; break; fi ;;
    esac
  done < <(curl -sS -N --max-time "${2:-1200}" -b "$JAR" "$API/runs/$id/events")
  echo "  SSE: $n events ($(echo $counts | tr ' ' '\n' | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}'))"
  echo "$last" | jq -c '{id, status, pause_reason, hosts_up: .stats.hosts_up, services: .stats.services_open, packets: .stats.packets_sent, http_requests: .stats.http_requests, avg_pps: .stats.avg_pps, elapsed_sec: .stats.elapsed_sec}' 2>/dev/null
}
wait_status() { # run id, jq condition, timeout seconds
  local id=$1 cond=$2 t=${3:-300} i=0
  while [ $i -lt "$t" ]; do
    if api GET "/runs/$id" 2>/dev/null | jq -e "$cond" >/dev/null 2>&1; then return 0; fi
    sleep 1; i=$((i + 1))
  done
  return 1
}
wait_done() { wait_status "$1" '.status == "completed" or .status == "failed" or .status == "cancelled"' "${2:-900}"; }
hm() { printf "%02d:%02d" $(( ($1 / 60) % 24 )) $(( $1 % 60 )); }

step "0. Preconditions"
for tool in docker curl jq awk; do command -v $tool >/dev/null || { echo "missing tool: $tool"; exit 2; }; done
echo "docker $(docker version --format '{{.Server.Version}}'); scope: $NET $P.0.0/22 (created by this script)"

step "1. Target network with real services"
e2e/full/lab.sh up
sleep 5

step "2. Start the product with compose (Czujka joins $NET through deploy/docker-compose.scan-network.yml)"
$DC down -v --remove-orphans >/dev/null 2>&1 || true
if [ "${E2E_SKIP_BUILD:-0}" = 1 ]; then $DC up -d --wait 2>&1 | grep -E "Healthy|rror" || true
else $DC up -d --build --wait 2>&1 | grep -E "Healthy|rror" || true; fi
HZ=$(curl -sS $BASE/healthz)
echo "$HZ" | jq -c '{status, tde, engine, probe}'
check "healthz: engine and prober" "$(echo "$HZ" | jq -r '"engine=\(.engine) mode=\(.probe.mode)"')" "engine=true mode=nmap-raw"
check "process user in the container" "$(docker exec $CZ id -u)" "10001"
check "web UI served by the binary on the same port" "$(curl -sS $BASE/ | grep -c '<div id="root">')" "1"
LABIF=$(labif)
CZIP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" $CZ)
echo "Czujka address on the target network: $CZIP ($LABIF)"

step "3. Log in"
LOGIN=$(curl -sS -c "$JAR" -H "Content-Type: application/json" -d "{\"email\":\"$ADMIN\",\"password\":\"$ADMIN_PW\"}" $API/auth/login)
CSRF=$(echo "$LOGIN" | jq -r .csrf_token)
check "login" "$(echo "$LOGIN" | jq -r .user.role_slug)" "admin"

step "4. Safety policy: never touch Czujka's own address or the network gateway"
# The gateway is the docker host side of the network, not a lab host: excluded too.
POL=$(api GET /settings/safety | jq -c --arg ip "$CZIP" --arg gw "$P.0.1" '.exclusions = [$ip, $gw]')
api PUT /settings/safety "$POL" | jq -c '{max_pps, max_http_rps, max_per_host_rps, exclusions, allowed_methods}'

step "5. Scope and profile"
SCOPE=$(api POST /scopes '{"name":"Laboratorium e2e","description":"sieć dockera czfull-net","criticality":3}' | jq -r .id)
api POST /scopes/$SCOPE/targets "{\"text\":\"$P.0.0/22\"}" | jq -c '{saved: (.valid | length), address_count, excluded, invalid: (.invalid | length)}'
PROFILE_JSON=$(jq -nc --argjson s "$SCOPE" '{name:"e2e: pełny skan", scope_ids:[$s], ports:"top-1000,6379,8765,9443", service_detection:true, version_intensity:5,
  http:{enabled:true, max_redirects:3, signature_paths:true, favicon:true, timeout_ms:5000},
  rate:{max_pps:800, max_parallel_chunks:2, max_parallel_hosts:8, http_rps:20},
  retry:{unstable_retries:1}, schedule:{enabled:false}, enabled:true}')
PROFILE=$(api POST /profiles "$PROFILE_JSON" | jq -r .id)
echo "profile $PROFILE"
case "$PROFILE" in ''|null) echo "the profile could not be created: stopping"; exit 1 ;; esac
EST=$(api POST /profiles/$PROFILE/estimate)
echo "$EST" | jq -c .
checkge "estimate: addresses (1024 minus Czujka and the gateway)" "$(echo "$EST" | jq .addresses)" 1022

step "6. Run 1: start, follow the SSE stream to the end"
mem_sampler
T0=$(date +%s)
RUN1=$(api POST /runs "{\"profile_id\":$PROFILE}" | jq -r .id)
follow "$RUN1"
wait_done "$RUN1" 120
D1=$(( $(date +%s) - T0 ))
R1=$(api GET /runs/$RUN1)
check "run 1 status" "$(echo "$R1" | jq -r .status)" "completed"
check "run 1 hosts up (the 9 lab hosts)" "$(echo "$R1" | jq .stats.hosts_up)" "9"

step "7. Results of run 1"
echo "-- hosts:"
api GET "/hosts?limit=100&sort=ip" | jq -r '.items[] | "  \(.ip) status=\(.status) ports=\(.open_ports | map(tostring) | join(",")) tech=\(.technologies | join(",")) interest=\(.interest)"'
echo "-- services with technologies, versions, classes and interest reasons:"
api GET "/services?limit=100&sort=-interest" | jq -r '.items[] | "  \(.ip):\(.port) \(.name) | \(.product) \(.version) | title=\(.title) | tech=\([.technologies[] | .name + (if .version != "" then " " + .version else "" end)] | join(", ")) | classes=\(.classes | join(",")) | interest=\(.interest) why=\([.interest_why[] | "\(.code)+\(.points)"] | join(" "))"'
SVC=$(api GET "/services?limit=200")
check "nginx found with its version" "$(echo "$SVC" | jq -r --arg ip "$P.0.10" '[.items[] | select(.ip == $ip and .port == 80)][0] | "\(.product) \(.version)"')" "nginx 1.24.0"
check "WordPress recognised" "$(echo "$SVC" | jq -r --arg ip "$P.1.80" '[.items[] | select(.ip == $ip) | .technologies[].name] | index("WordPress") != null')" "true"
check "Grafana recognised" "$(echo "$SVC" | jq -r --arg ip "$P.2.90" '[.items[] | select(.ip == $ip) | .technologies[].name] | index("Grafana") != null')" "true"
check "MariaDB classified as database" "$(echo "$SVC" | jq -r --arg ip "$P.1.81" '[.items[] | select(.ip == $ip and .port == 3306)][0].classes | index("database") != null')" "true"
check "host that drops ICMP found" "$(api GET "/hosts?limit=100" | jq -r --arg ip "$P.3.60" '[.items[] | select(.ip == $ip)][0].status')" "up"
check "TLS service on 9443" "$(echo "$SVC" | jq -r --arg ip "$P.3.50" '[.items[] | select(.ip == $ip and .port == 9443)][0].tls')" "true"
check "Czujka and the gateway were not scanned (exclusions)" "$(api GET "/hosts?limit=100" | jq -r --arg ip "$CZIP" --arg gw "$P.0.1" '[.items[] | select(.ip == $ip or .ip == $gw)] | length')" "0"
check "Redis found on 6379" "$(echo "$SVC" | jq -r --arg ip "$P.1.30" '[.items[] | select(.ip == $ip and .port == 6379)][0].product')" "Redis key-value store"
echo "-- findings:"
api GET "/findings?limit=100" | jq -r '.items[] | "  #\(.id) [\(.status)] \(.type) \(.ip):\(.port) interest=\(.interest)  \(.title)"'
checkge "findings of run 1" "$(api GET /findings | jq .total)" 3
echo "-- dashboard:"
api GET /dashboard | jq -c 'del(.timeline, .top_services, .top_findings, .recent_changes, .technologies) ' | cut -c1-600

step "8. Analyst edits before the second run"
NGINX_SVC=$(echo "$SVC" | jq -r --arg ip "$P.0.10" '[.items[] | select(.ip == $ip and .port == 80)][0].id')
api PATCH /services/$NGINX_SVC '{"note":"reverse proxy laboratorium","tags":["e2e"]}' | jq -c '{id, product, version, note, tags}'
DBF=$(api GET "/findings?limit=100&type=database-exposed" | jq -r '.items[0].id')
api PATCH /findings/$DBF '{"status":"accepted","note":"baza testowa, ryzyko zaakceptowane"}' | jq -c '{id, type, status, note}'

step "9. Custom signature through the API; retro-hunt with 0 packets"
SIGYAML=$'id: e2e-lab-page\nname: Strona laboratorium e2e\ncategory: other\ninterest: 20\nbody: \'lab host\''
api POST /signatures "$(jq -nc --arg y "$SIGYAML" '{yaml: $y}')" | jq -c '{id, slug, name, enabled}'
cap_start
RH=$(api POST /signatures/retrohunt "$(jq -nc --arg y "$SIGYAML" '{yaml: $y, latest_only: true}')")
sleep 1
cap_stop "$TMP/retrohunt.cap.txt"
echo "$RH" | jq -c '{scanned, total_hits, hits: [.hits[]? | "\(.ip):\(.port)"]}'
checkge "retro-hunt hits in stored observations" "$(echo "$RH" | jq .total_hits)" 3
# Traffic to the gateway is the docker host side (API replies, ARP refresh for them), not a lab host.
check "packets sent to lab hosts during the retro-hunt (tcpdump)" "$(grep -v -e "who-has $P.0.1 " -e "> $P.0.1\." "$TMP/retrohunt.cap.txt" | wc -l | tr -d ' ')" "0"

step "10. Change the target network: redis stops, a new nginx host, nginx upgraded, one page title changed"
e2e/full/lab.sh change

step "11. Run 2 and the diff"
T0=$(date +%s)
RUN2=$(api POST /runs "{\"profile_id\":$PROFILE}" | jq -r .id)
follow "$RUN2"
wait_done "$RUN2" 120
D2=$(( $(date +%s) - T0 ))
R2=$(api GET /runs/$RUN2)
check "run 2 status" "$(echo "$R2" | jq -r .status)" "completed"
echo "$R2" | jq -c .summary
echo "-- changes of run 2:"
CH=$(api GET "/changes?run_id=$RUN2&limit=200")
echo "$CH" | jq -r '.items[] | "  \(.kind) [\(.severity)] \(.summary)"'
check "new host reported" "$(echo "$CH" | jq -r --arg ip "$P.0.11" '[.items[] | select(.ip == $ip and (.kind == "host_new" or .kind == "service_new"))] | length > 0')" "true"
check "nginx version change reported" "$(echo "$CH" | jq -r --arg ip "$P.0.10" '[.items[] | select(.ip == $ip and (.kind == "tech_version" or .kind == "service_changed"))] | length > 0')" "true"
check "page title change reported" "$(echo "$CH" | jq -r --arg ip "$P.2.40" '[.items[] | select(.ip == $ip)] | length > 0')" "true"
check "silent redis host reported" "$(echo "$CH" | jq -r --arg ip "$P.1.30" '[.items[] | select(.ip == $ip and (.kind == "host_unstable" or .kind == "host_gone" or .kind == "host_missing"))] | length > 0')" "true"
DIFF=$(api GET "/diff?from=$RUN1&to=$RUN2")
echo "$DIFF" | jq -c '{from, to, by_kind: .summary.by_kind}'
checkge "diff of run 1 and run 2 lists changes" "$(echo "$DIFF" | jq '.changes | length')" 4
check "custom signature matched in run 2" "$(api GET "/services?limit=200" | jq -r '[.items[].technologies[] | select(.sources | index("e2e-lab-page"))] | length > 0')" "true"
checkge "custom signature match count" "$(api GET "/signatures?q=e2e-lab-page" | jq -r '.items[0].match_count')" 3
S=$(api GET /services/$NGINX_SVC)
check "service edit survives the second scan" "$(echo "$S" | jq -r '"\(.note) | \(.tags | join(",")) | \(.version)"')" "reverse proxy laboratorium | e2e | 1.30.7"
F=$(api GET /findings/$DBF)
check "finding triage survives the second scan" "$(echo "$F" | jq -r '"\(.status) | \(.note) | last_run=\(.last_run_id)"')" "accepted | baza testowa, ryzyko zaakceptowane | last_run=$RUN2"

step "12. Run report (HTML and Markdown)"
check "report.html" "$(curl -sS -b "$JAR" -o $TMP/r.html -w '%{http_code} %{content_type}' $API/runs/$RUN2/report.html)" "200 text/html; charset=utf-8"
check "report.md" "$(curl -sS -b "$JAR" -o $TMP/r.md -w '%{http_code}' $API/runs/$RUN2/report.md)" "200"
head -12 $TMP/r.md | sed 's/^/  | /'

step "13. Exports re-import"
for fmt in json csv xml; do
  curl -sS -b "$JAR" -o $TMP/run2.$fmt $API/export/runs/$RUN2.$fmt
  IMP=$(upload /import/results $TMP/run2.$fmt)
  echo "  $fmt: $(wc -c < $TMP/run2.$fmt | tr -d ' ') bytes -> $(echo "$IMP" | jq -c '{format, run_id, hosts, services, invalid: (.invalid | length)}')"
  check "$fmt export imports again: hosts (live and silent) and open services" "$(echo "$IMP" | jq -r '"hosts=\(.hosts) services=\(.services)"')" "hosts=$(api GET "/hosts?limit=1" | jq .total) services=$(echo "$R2" | jq .stats.services_open)"
done

step "14. Signature file import (one valid, one unsafe)"
cat > $TMP/sigs.yaml <<'EOF'
- id: e2e-import-ok
  name: Import e2e
  body: 'Czujka lab'
- id: e2e-import-unsafe
  name: Niebezpieczna
  requests:
    - {path: /login, method: POST, body: 'user=admin&pass=admin'}
  body: 'x'
EOF
SI=$(upload /signatures/import $TMP/sigs.yaml)
echo "$SI" | jq -c '{created, updated, skipped, issues: [.validation.issues[]? | "\(.level) \(.path): \(.message)"]}'
check "signature import stores the valid one" "$(echo "$SI" | jq -r '.created | join(",")')" "e2e-import-ok"
checkge "signature import rejects the unsafe one with a reason" "$(echo "$SI" | jq '[.validation.issues[]? | select(.level == "error")] | length')" 1

step "15. Passive sources"
printf 'hostname,ip,source\nwww.kampus.test,%s,dns\nnowy.kampus.test,%s,dns\nobcy.example.org,192.0.2.10,dns\n' "$P.1.80" "$P.0.12" > $TMP/pdns.csv
PI=$(upload /passive/import $TMP/pdns.csv)
echo "$PI" | jq -c '{candidates: [.candidates[]? | "\(.value) \(.sources | join(","))"], hints: [.hints[]? | "\(.ip) \(.hostnames | join(","))"], out_of_scope: [.out_of_scope[]? | .ip]}'
check "passive file: the address outside the scope is not a candidate" "$(echo "$PI" | jq -r '[.candidates[]?.value] | index("192.0.2.10") == null')" "true"
CAND=$(echo "$PI" | jq -c --arg ip "$P.0.12" '[.candidates[]? | select(.value == $ip) | {value, sources}]')
PC=$(api POST /passive/confirm "$(jq -nc --argjson s "$SCOPE" --argjson c "$CAND" '{scope_id: $s, candidates: $c}')")
check "passive confirm adds the candidate to the scope" "$(echo "$PC" | jq -r '[.valid[]? | select(.source == "passive")] | length')" "1"
PTR=$(api POST /passive/ptr)
echo "$PTR" | jq -c '{hints: [.hints[]? | "\(.ip) \(.hostnames | join(","))"][:4], hosts_updated}'
checkge "PTR lookups added hostnames to known hosts" "$(echo "$PTR" | jq .hosts_updated)" 1
check "crt.sh stays off until an admin enables it" "$(status_of POST /passive/crtsh)" "409"

step "16. Scan window closes mid-run; the scheduler resumes the run in the next window"
NOWM=$(( 10#$(TZ=Europe/Warsaw date +%H) * 60 + 10#$(TZ=Europe/Warsaw date +%M) ))
SEC=$(( 10#$(date +%S) ))
W1E=$(( NOWM + 2 )); [ "$SEC" -gt 40 ] && W1E=$(( NOWM + 3 ))
W2S=$(( W1E + 1 )); W2E=$(( W2S + 25 ))
WIN=$(jq -nc --arg a "$(hm $NOWM)" --arg b "$(hm $W1E)" --arg c "$(hm $W2S)" --arg d "$(hm $W2E)" \
  '[{days:[0,1,2,3,4,5,6], start:$a, end:$b}, {days:[0,1,2,3,4,5,6], start:$c, end:$d}]')
echo "windows (Europe/Warsaw): $WIN"
WP=$(api POST /profiles "$(jq -nc --argjson s "$SCOPE" --argjson w "$WIN" '{name:"e2e: okno", scope_ids:[$s], ports:"22,80", service_detection:false,
  http:{enabled:false}, rate:{max_pps:40, max_parallel_chunks:1}, chunking:{adaptive:false, initial_size:256, min_size:256, max_size:256, target_seconds:30},
  schedule:{enabled:true, interval_minutes:1440, windows:$w, timezone:"Europe/Warsaw"}, enabled:true}')" | jq -r .id)
RW=$(api POST /runs "{\"profile_id\":$WP}" 2>/dev/null | jq -r '.id // empty')
if [ -z "$RW" ]; then RW=$(api GET "/runs?profile_id=$WP&limit=1" | jq -r '.items[0].id'); echo "  (the scheduler started the run first)"; fi
case "$WP" in ''|null) fail "the window profile could not be created" ;; esac
echo "window run $RW started at $(TZ=Europe/Warsaw date +%H:%M:%S); window 1 closes at $(hm $W1E):00"
if wait_status "$RW" '.status == "paused" and .pause_reason == "window_closed"' 260; then
  RWJ=$(api GET /runs/$RW)
  pass "run paused at $(TZ=Europe/Warsaw date +%H:%M:%S) with window_closed, resume_at=$(echo "$RWJ" | jq -r .resume_at), chunks $(echo "$RWJ" | jq -r '"\(.stats.chunks_done)/\(.stats.chunks_total)"')"
  checkge "chunks finished before the window closed (the window closed mid-run)" "$(echo "$RWJ" | jq .stats.chunks_done)" 1
  echo "-- chunks of the paused run:"
  api GET /runs/$RW/chunks | jq -r '.[] | "  chunk \(.seq) \(.spec | join(",")) \(.status) hosts_up=\(.hosts_up) group=\(.group)"'
  check "no service reported gone outside the scanned ports 22,80" "$(api GET "/changes?run_id=$RW&kind=service_gone&limit=200" | jq '[.items[] | select(.port != 22 and .port != 80)] | length')" "0"
else
  fail "run did not pause with window_closed: $(api GET /runs/$RW | jq -c '{status, pause_reason, window_end}')"
fi
WAIT2=$(( W2S * 60 - NOWM * 60 - SEC + 90 ))
if wait_status "$RW" '.status == "running" or .status == "analyzing" or .status == "completed"' "$WAIT2"; then
  pass "the scheduler resumed the run at $(TZ=Europe/Warsaw date +%H:%M:%S) (window 2 opens at $(hm $W2S):00)"
else
  fail "run was not resumed: $(api GET /runs/$RW | jq -c '{status, pause_reason, resume_at}')"
fi
wait_done "$RW" 900
check "window run completed after the resume" "$(api GET /runs/$RW | jq -r .status)" "completed"
api PATCH /profiles/$WP '{"schedule":{"enabled":false}}' >/dev/null

step "17. Emergency stop during a run"
SP=$(api POST /profiles "$(jq -nc --argjson s "$SCOPE" '{name:"e2e: stop", scope_ids:[$s], ports:"top-1000", service_detection:true, http:{enabled:true}, rate:{max_pps:200}, enabled:true}')" | jq -r .id)
RS=$(api POST /runs "{\"profile_id\":$SP}" | jq -r .id)
wait_status "$RS" '.status == "running" and .stats.packets_sent > 0' 60 || sleep 5
sleep 2
cap_start
NM0=$(docker exec $CZ sh -c 'pgrep nmap | wc -l')
TS=$(date +%s.%N)
ES=$(api POST /emergency-stop)
TE=$(date +%s.%N)
sleep 1
NM1=$(docker exec $CZ sh -c 'pgrep nmap | wc -l')
sleep 3
cap_stop "$TMP/stop.pcap.txt"
awk -v t="$TS" '$1+0 > t' "$TMP/stop.pcap.txt" > "$TMP/stop.after.txt" || true
IP_LATE=$(awk -v t="$TS" '$1+0 > t+1 && $2 == "IP"' "$TMP/stop.after.txt" | wc -l | tr -d ' ')
IP_ANY=$(awk '$2 == "IP"' "$TMP/stop.after.txt" | wc -l | tr -d ' ')
ARP_ALL=$(grep -c ' ARP, ' "$TMP/stop.after.txt" || true)
ARP_LAST=$(grep ' ARP, ' "$TMP/stop.after.txt" | tail -1 | awk -v t="$TS" '{printf "%.1f", $1 - t}')
BEFORE=$(awk -v t="$TS" '$1+0 <= t' "$TMP/stop.pcap.txt" | wc -l | tr -d ' ')
echo "  nmap processes before the stop: $NM0; one second after: $NM1; the stop call took $(echo "$TE - $TS" | bc) s"
echo "  packets leaving the scan interface: $BEFORE in the 3 s before the stop; after the stop: $IP_ANY IP packets (SYN/ICMP/HTTP), $IP_LATE of them later than 1 s"
echo "  after the stop the kernel still sent $ARP_ALL ARP requests (neighbour retries for addresses nmap had probed; the last at +${ARP_LAST:-0} s)"
check "emergency flag set" "$(echo "$ES" | jq -r .emergency_stop)" "true"
check "no nmap process one second after the stop" "$(echo $NM1)" "0"
checkge "scan packets were flowing before the stop" "$BEFORE" 1
check "no IP packet (SYN, ICMP, HTTP) to the target network later than 1 s after the stop" "$IP_LATE" "0"
check "run paused by the emergency stop" "$(api GET /runs/$RS | jq -r '"\(.status) \(.pause_reason)"')" "paused emergency_stop"
check "a new run is refused while the stop is active" "$(status_of POST /runs "{\"profile_id\":$SP}")" "409"
api POST /emergency-stop/release | jq -c '{emergency_stop}'
api POST /runs/$RS/cancel | jq -c '{id, status}'

step "18. Measurements"
rm -f "$TMP/mem.on"; sleep 2
MAXPPS=800; HTTPRPS=20
for r in "$RUN1:$D1" "$RUN2:$D2"; do
  id=${r%%:*}; wall=${r##*:}
  api GET /runs/$id | jq -r --arg wall "$wall" --argjson cap $MAXPPS --argjson hcap $HTTPRPS \
    '"  run \(.id): wall \($wall) s, active \(.stats.elapsed_sec) s, hosts \(.stats.hosts_up), services \(.stats.services_open), packets \(.stats.packets_sent) (avg \(.stats.avg_pps | floor) pps, cap \($cap) pps), HTTP requests \(.stats.http_requests) (\(if .stats.elapsed_sec > 0 then ((.stats.http_requests / .stats.elapsed_sec * 10 | floor) / 10) else 0 end) req/s on average, cap \($hcap) req/s)"'
  checkle "run $id average packet rate under the cap" "$(api GET /runs/$id | jq '.stats.avg_pps | floor')" $MAXPPS
done
echo "  memory of the Czujka container during the scans: max $(mem_max) MiB over $(wc -l < $TMP/mem.txt | tr -d ' ') samples"

step "Result"
echo "PASS: $PASSES  FAIL: $FAILS"
if [ "$FAILS" -gt 0 ]; then exit 1; fi
echo "E2E FULL OK: every check passed"
