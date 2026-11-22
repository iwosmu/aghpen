#!/bin/bash
# End-to-end check of the Czujka core with real components and no scan run:
# the product stack (PostgreSQL with pg_tde + czujka), a real nmap XML file and
# the local DefectDojo of lab/defectdojo.
#
#   docker compose -f lab/defectdojo/docker-compose.yml up -d    # once, takes about a minute
#   make e2e-core
#
# Environment: E2E_PORT (18090), E2E_PROJECT (czujka-e2e), E2E_KEEP=1 keeps the stack,
# DOJO_URL (http://127.0.0.1:18080), DOJO_URL_INSIDE (http://host.docker.internal:18080), DOJO_TOKEN.
set -euo pipefail
cd "$(dirname "$0")/.."
PROJECT=${E2E_PROJECT:-czujka-e2e}
PORT=${E2E_PORT:-18090}
BASE=http://127.0.0.1:$PORT
API=$BASE/api/v1
DOJO_URL=${DOJO_URL:-http://127.0.0.1:18080}
DOJO_URL_INSIDE=${DOJO_URL_INSIDE:-http://host.docker.internal:18080}
# The token of the lab instance is public (lab/defectdojo/README.md); the instance listens on 127.0.0.1 only.
DOJO_TOKEN=${DOJO_TOKEN:-$(sed -n 's/.*Token API v2 | `\([0-9a-f]*\)`.*/\1/p' lab/defectdojo/README.md)}
SAMPLE=lab/defectdojo/sample-nmap.xml
ADMIN=admin@czujka.local
ADMIN_PW="E2e-$(date +%s)-$RANDOM$RANDOM"
STAMP=$(date +%Y%m%d-%H%M%S)
TMP=$(mktemp -d)
JAR=$TMP/jar
CSRF=
FAILS=0
DC="docker compose -p $PROJECT -f deploy/docker-compose.yml"
export CZUJKA_PORT=$PORT CZUJKA_VERSION=e2e CZUJKA_ADMIN_EMAIL=$ADMIN CZUJKA_ADMIN_PASSWORD=$ADMIN_PW

cleanup() {
  if [ "${E2E_KEEP:-0}" != 1 ]; then
    # Remove the two products that this run created in the lab DefectDojo, then the stack with its volumes.
    for name in "Czujka e2e $STAMP" "Czujka e2e auto $STAMP"; do
      id=$(curl -sS -G -H "Authorization: Token $DOJO_TOKEN" --data-urlencode "name=$name" "$DOJO_URL/api/v2/products/" 2>/dev/null | jq -r --arg n "$name" '.results[]? | select(.name == $n) | .id' 2>/dev/null | head -1 || true)
      if [ -n "${id:-}" ]; then curl -sS -o /dev/null -X DELETE -H "Authorization: Token $DOJO_TOKEN" "$DOJO_URL/api/v2/products/$id/" || true; fi
    done
    $DC down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

step() { echo; echo "=== $* ==="; }
check() { # description got want
  if [ "$2" = "$3" ]; then echo "  OK    $1: $2"; else echo "  FAIL  $1: got \"$2\", want \"$3\""; FAILS=$((FAILS + 1)); fi
}
api() { # method path [json body] -> response body; stops the script on an HTTP error
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
upload() { # path file -> response body
  local out code
  out=$(curl -sS -b "$JAR" -H "X-CSRF-Token: $CSRF" -F "file=@$2" -w "\n%{http_code}" "$API$1")
  code=${out##*$'\n'}
  if [ "$code" -ge 400 ]; then echo "HTTP $code for upload $1: ${out%$'\n'*}" >&2; return 1; fi
  printf "%s" "${out%$'\n'*}"
}
dojo() { curl -sS -H "Authorization: Token $DOJO_TOKEN" "$DOJO_URL/api/v2$1"; }

step "0. Preconditions"
for tool in docker curl jq perl; do command -v $tool >/dev/null || { echo "missing tool: $tool"; exit 2; }; done
if ! dojo "/user_profile/" | jq -e .user.username >/dev/null 2>&1; then
  echo "DefectDojo does not answer at $DOJO_URL. Start it: docker compose -f lab/defectdojo/docker-compose.yml up -d"; exit 2
fi
echo "DefectDojo answers at $DOJO_URL (user $(dojo "/user_profile/" | jq -r .user.username))"

step "1. Start the stack from a clean state"
$DC down -v --remove-orphans >/dev/null 2>&1 || true
$DC up -d --build --wait 2>&1 | grep -E "Healthy|Error|error" || true
check "healthz without a session: status and version only" "$(curl -sS $BASE/healthz | jq -r 'keys | join(",")')" "status,version"

step "2. Log in; the first start seeded a safety policy and one profile, nothing else"
LOGIN=$(curl -sS -c "$JAR" -H "Content-Type: application/json" -d "{\"email\":\"$ADMIN\",\"password\":\"$ADMIN_PW\"}" $API/auth/login)
CSRF=$(echo "$LOGIN" | jq -r .csrf_token)
echo "$LOGIN" | jq -c "{user: .user.email, role: .user.role_slug, permissions: (.permissions | length)}"
curl -sS -b "$JAR" $BASE/healthz | jq -c "{status, db, tde, tables: .tde_detail.tables, encrypted: .tde_detail.encrypted, engine}"
check "healthz with a session" "$(curl -sS -b "$JAR" $BASE/healthz | jq -r '"\(.status) tde=\(.tde) engine=\(.engine)"')" "ok tde=true engine=true"
api GET /settings/safety | jq -c "{max_pps, max_http_rps, max_per_host_rps, allowed_methods, emergency_stop}"
api GET /profiles | jq -c '.items[] | {name, ports, max_pps: .rate.max_pps, scope_ids, schedule_enabled: .schedule.enabled}'
check "seed" "profiles=$(api GET /profiles | jq .total) hosts=$(api GET /hosts | jq .total) findings=$(api GET /findings | jq .total) scopes=$(api GET /scopes | jq .total)" "profiles=1 hosts=0 findings=0 scopes=0"

step "3. Create a scope"
SCOPE=$(api POST /scopes '{"name":"Lab e2e","criticality":4,"owner":"CBI"}' | jq .id)
api POST /scopes/$SCOPE/targets '{"text":"172.31.250.0/24"}' | jq -c "{valid: (.valid | length), address_count, invalid: (.invalid | length)}"

step "4. Import a real nmap XML file ($SAMPLE)"
R1=$(upload /import/results $SAMPLE)
echo "$R1" | jq -c .
RUN1=$(echo "$R1" | jq .run_id)
api GET /runs/$RUN1 | jq -c "{id, status, trigger, import_file, hosts_up: .stats.hosts_up, services_open: .stats.services_open, summary}"
check "run 1" "$(api GET /runs/$RUN1 | jq -r '"\(.status) changes=\(.summary.by_kind | length)"')" "completed changes=0"
echo "-- services with their interest score and reasons:"
api GET "/services?state=open&sort=-interest" | jq -r '.items[] | "  \(.ip):\(.port) \(.product) \(.version)  interest=\(.interest)  classes=\(.classes | join(","))  why=\([.interest_why[] | "\(.code)+\(.points)"] | join(" "))"'
echo "-- findings derived from the import:"
api GET "/findings?sort=-interest" | jq -r '.items[] | "  #\(.id) [\(.status)] \(.type) \(.ip):\(.port) interest=\(.interest)  \(.title)"'
F1=$(api GET /findings | jq .total)
check "scope match" "$(api GET "/hosts?scope_id=$SCOPE" | jq .total)" "4"

step "5. Analyst edits"
SVC=$(api GET "/services?port=80&q=nginx" | jq ".items[0].id")
api PATCH /services/$SVC '{"product":"nginx (reverse proxy dziekanatu)","note":"zgloszone do DSI","tags":["dziekanat"]}' | jq -c "{id, product, version, note, tags, override: .overrides.product}"
FIND=$(api GET "/findings?type=database-exposed" | jq ".items[0].id")
api PATCH /findings/$FIND '{"status":"accepted","note":"baza testowa, ryzyko zaakceptowane","assignee":"ola"}' | jq -c "{id, type, status, note, assignee}"

step "6. Import a second, modified file (new nginx version, SSH opened, Apache closed, one host silent)"
perl deploy/e2e/modify-nmap.pl $SAMPLE > "$TMP/second.xml"
{ diff <(tr ">" ">\n" < $SAMPLE) <(tr ">" ">\n" < "$TMP/second.xml") || true; } | grep -c "^[<>]" | xargs echo "  changed XML tokens:"
R2=$(upload /import/results "$TMP/second.xml")
echo "$R2" | jq -c .
RUN2=$(echo "$R2" | jq .run_id)
api GET /runs/$RUN2 | jq -c "{id, status, summary}"
echo "-- changes of run $RUN2:"
api GET "/changes?run_id=$RUN2&sort=id" | jq -r '.items[] | "  \(.kind) [\(.severity)] \(.summary)"'
# A host silent once is reported missing and unconfirmed (host_missing); a second miss confirms it (host_gone).
check "changes" "$(api GET "/changes?run_id=$RUN2&limit=500" | jq -r '[.items[].kind] | unique | join(",")')" "headers_changed,host_missing,service_changed,service_gone,service_new,tech_version"
check "the silent host is missing, unconfirmed" "$(api GET "/changes?run_id=$RUN2&limit=500" | jq -r '[.items[] | select(.kind == "host_missing") | .ip] | join(",")')" "172.31.250.5"
echo "-- hosts after run $RUN2 (stability model):"
api GET "/hosts?sort=ip" | jq -r '.items[] | "  \(.ip) status=\(.status) p_alive=\(.p_alive) misses=\(.consecutive_misses) interest=\(.interest) open_ports=\(.open_ports | map(tostring) | join(","))"'
SILENT=$(api GET "/hosts?cidr=172.31.250.5" | jq ".items[0].id")
api GET /hosts/$SILENT/availability | jq -c "{p_alive, down_after_misses, recent: [.recent[] | {run_id, up}]}"
check "silent host" "$(api GET /hosts/$SILENT | jq -r .status)" "unstable"
echo "-- findings after run $RUN2:"
api GET "/findings?sort=id&limit=100" | jq -r '.items[] | "  #\(.id) [\(.status)] \(.type) \(.ip):\(.port) first_run=\(.first_run_id) last_run=\(.last_run_id)"'
check "new findings from the new SSH service" "$(api GET "/findings?limit=100" | jq "[.items[] | select(.first_run_id == $RUN2)] | length")" "2"
check "finding of the closed Apache port" "$(api GET "/findings?limit=100" | jq -r '[.items[] | select(.ip == "172.31.250.3")][0].status')" "resolved"
echo "-- the edits survive the second import:"
api GET /services/$SVC | jq -c "{product, version, note, tags, observed_product: .overrides.product.observed, by: .overrides.product.by}"
check "service override" "$(api GET /services/$SVC | jq -r '"\(.product) / \(.version) / \(.note)"')" "nginx (reverse proxy dziekanatu) / 1.33.0 / zgloszone do DSI"
check "finding triage" "$(api GET /findings/$FIND | jq -r '"\(.status) / \(.note) / last_run=\(.last_run_id)"')" "accepted / baza testowa, ryzyko zaakceptowane / last_run=$RUN2"

step "7. Diff of the two runs (GET /diff?from=$RUN1&to=$RUN2)"
api GET "/diff?from=$RUN1&to=$RUN2" | jq -c "{from: .from.id, to: .to.id, summary: .summary, changes: [.changes[] | \"\(.kind) \(.ip):\(.port)\"]}"
check "diff" "$(api GET "/diff?from=$RUN1&to=$RUN2" | jq -r '"new=\(.summary.services_new) gone=\(.summary.services_gone) changed=\(.summary.services_changed)"')" "new=1 gone=1 changed=1"

step "8. DefectDojo: settings, connection test, export of findings (twice), nmap XML of the run (twice)"
api PUT /settings/defectdojo "{\"enabled\":true,\"url\":\"$DOJO_URL_INSIDE\",\"api_key\":\"$DOJO_TOKEN\",\"product_name\":\"Czujka e2e $STAMP\",\"engagement_name\":\"e2e $STAMP\"}" | jq -c .
check "the API key is not returned" "$(api GET /settings/defectdojo | jq -r '"\(.api_key // "absent") set=\(.api_key_set)"')" "absent set=true"
$DC exec -T db psql -h 127.0.0.1 -U czujka -d czujka -Atc "SELECT 'stored as: ' || left(secret, 40) || '... (' || length(secret) || ' chars)' FROM settings WHERE key = 'defectdojo'"
check "the API key is not in the database in clear text" "$($DC exec -T db psql -h 127.0.0.1 -U czujka -d czujka -Atc "SELECT count(*) FROM settings WHERE value::text LIKE '%$DOJO_TOKEN%' OR secret LIKE '%$DOJO_TOKEN%'")" "0"
api POST /settings/defectdojo/test "{}" | jq -c .
OPEN=$(api GET "/findings?status=new,triaged,accepted&limit=500" | jq .total)
E1=$(api POST /findings/export/defectdojo '{"filter":{"status":["new","triaged","accepted"]}}')
echo "first export:  $(echo "$E1" | jq -c .)"
TEST_ID=$(echo "$E1" | jq .test_id)
N1=$(dojo "/findings/?test=$TEST_ID&limit=1" | jq .count)
E2=$(api POST /findings/export/defectdojo '{"filter":{"status":["new","triaged","accepted"]}}')
echo "second export: $(echo "$E2" | jq -c .)"
N2=$(dojo "/findings/?test=$TEST_ID&limit=1" | jq .count)
check "first export creates" "$(echo "$E1" | jq -r '"exported=\(.exported) updated=\(.updated) failed=\(.failed)"')" "exported=$OPEN updated=0 failed=0"
check "second export updates, no duplicates" "$(echo "$E2" | jq -r '"exported=\(.exported) updated=\(.updated) failed=\(.failed)"')" "exported=0 updated=$OPEN failed=0"
check "findings in the DefectDojo test after export 1 and 2" "$N1 $N2" "$OPEN $OPEN"
echo "-- dojo_id and dojo_url written back:"
api GET "/findings?exported=true&sort=id" | jq -r '.items[] | "  #\(.id) \(.type) -> dojo_id=\(.dojo_id) \(.dojo_url)"'
echo "-- the same findings as DefectDojo holds them:"
dojo "/findings/?test=$TEST_ID&limit=50" | jq -r '.results[] | "  dojo #\(.id) [\(.severity)] \(.title)  unique_id=\(.unique_id_from_tool)"'
U1=$(api POST /runs/$RUN2/export/defectdojo)
echo "nmap XML upload 1: $(echo "$U1" | jq -c .)"
U2=$(api POST /runs/$RUN2/export/defectdojo)
echo "nmap XML upload 2: $(echo "$U2" | jq -c .)"
check "nmap upload: first imports, second re-imports into the same test" "$(echo "$U1" | jq -r .reimport) $(echo "$U2" | jq -r .reimport) $([ "$(echo "$U1" | jq .test_id)" = "$(echo "$U2" | jq .test_id)" ] && echo same-test)" "false true same-test"

step "9. JSON, CSV and XML exports of run $RUN2 import again without a change"
# Each re-import is a new run. The file still says that 172.31.250.5 does not answer, so every
# re-import is one more miss for that host: the stability model may now report it inactive.
# That is a host status change, not a loss of data, so the check counts service changes.
curl -sS -b "$JAR" -o "$TMP/run.json" "$API/export/runs/$RUN2.json"
EXPORTED=$(jq '[.hosts[].services | length] | add' "$TMP/run.json")
for fmt in json csv xml; do
  curl -sS -b "$JAR" -o "$TMP/run.$fmt" "$API/export/runs/$RUN2.$fmt"
  REP=$(upload /import/results "$TMP/run.$fmt")
  RN=$(echo "$REP" | jq .run_id)
  DIFF=$(api GET "/diff?from=$RUN2&to=$RN")
  SVC_CH=$(echo "$DIFF" | jq '[.changes[] | select(.kind | startswith("host_") | not)] | length')
  HOST_CH=$(echo "$DIFF" | jq -r '[.changes[] | select(.kind | startswith("host_")) | "\(.kind) \(.ip)"] | join(", ")')
  SUMMARY=$(echo "$REP" | jq -c '{format, run_id, hosts, hosts_down, services, skipped, invalid: (.invalid | length)}')
  BYTES=$(wc -c < "$TMP/run.$fmt" | tr -d " ")
  echo "  $fmt: $BYTES bytes -> $SUMMARY"
  echo "       against run $RUN2: service changes: $SVC_CH; host status changes: ${HOST_CH:-none}"
  # The store keeps services that answered (open) and the ones it already knows; a port that the first file
  # lists as closed and that was never open is not kept. So the count to expect is the one in the exported JSON.
  # The export carries all four hosts of the run; the report counts the silent one apart (hosts_down).
  check "$fmt round trip" "$(echo "$REP" | jq -r '"hosts=\(.hosts) hosts_down=\(.hosts_down) services=\(.services) invalid=\(.invalid | length)"') service_changes=$SVC_CH" "hosts=3 hosts_down=1 services=$EXPORTED invalid=0 service_changes=0"
  if [ $fmt = json ]; then RJSON=$RN; fi
done
# Lossless: the Czujka JSON of the re-imported run equals the JSON it came from (run ids and file time aside).
curl -sS -b "$JAR" -o "$TMP/again.json" "$API/export/runs/$RJSON.json"
NORM='del(.generated_at, .run_id) | .hosts |= map(del(.run_id))'
check "Czujka JSON is lossless (export -> import -> export)" "$(diff <(jq -S "$NORM" "$TMP/run.json") <(jq -S "$NORM" "$TMP/again.json") >/dev/null && echo identical || echo different)" "identical"
echo "-- first lines of the Czujka JSON export:"; head -c 420 "$TMP/run.json"; echo " ..."
echo "-- CSV export:"; head -3 "$TMP/run.csv" | cut -c1-200
check "inventory after the re-imports" "hosts=$(api GET /hosts | jq .total) open_services=$(api GET "/services?state=open" | jq .total)" "hosts=4 open_services=3"

step "10. Automatic export after a run (auto_export with min_interest 25)"
api PUT /settings/defectdojo "{\"enabled\":true,\"url\":\"$DOJO_URL_INSIDE\",\"api_key\":\"$DOJO_TOKEN\",\"product_name\":\"Czujka e2e auto $STAMP\",\"engagement_name\":\"auto $STAMP\",\"auto_export\":true,\"min_interest\":25}" | jq -c "{product_name, auto_export, min_interest}"
RA=$(upload /import/results "$TMP/second.xml" | jq .run_id)
WANT=$(api GET "/findings?limit=500" | jq "[.items[] | select(.last_run_id == $RA and .interest >= 25 and (.status == \"new\" or .status == \"triaged\" or .status == \"accepted\"))] | length")
IN_DOJO=$(curl -sS -G -H "Authorization: Token $DOJO_TOKEN" --data-urlencode "product_name=Czujka e2e auto $STAMP" --data-urlencode "limit=50" "$DOJO_URL/api/v2/findings/")
echo "$IN_DOJO" | jq -r '.results[] | "  dojo #\(.id) [\(.severity)] \(.title)"'
api GET "/audit?limit=50" | jq -c '[.items[] | select(.action == "finding.export.defectdojo" and .detail.auto == true)][0] | {user_email, action, detail}'
check "run $RA exported its findings with interest >= 25 by itself" "$(echo "$IN_DOJO" | jq .count)" "$WANT"
check "at least one finding passed the threshold" "$([ "$WANT" -ge 1 ] && echo yes || echo no)" "yes"

step "11. Audit log of this flow"
api GET "/audit?limit=200" | jq -r '.items | reverse | .[] | select(.action | test("import|export|defectdojo|service.update|finding.update")) | "  \(.at[11:19]) \(.user_email) \(.action) \(.entity_id) status=\(.detail.status)"' | head -30

echo
if [ "$FAILS" -ne 0 ]; then echo "E2E FAILED: $FAILS check(s)"; exit 1; fi
echo "E2E OK: every check passed"
