#!/usr/bin/env bash
# Public-instance hardening on a real stack: the operator lock
# (CZUJKA_ALLOWED_NETWORKS), login throttling behind a trusted proxy and the
# security headers. It scans nothing: every refused target is refused before
# a run starts. Compose project czlock, port 127.0.0.1:18497.
#
#   ./e2e/lock/run.sh            build, check, remove the stack
#   E2E_KEEP=1 ./e2e/lock/run.sh keep the stack
set -uo pipefail
cd "$(dirname "$0")/../.."
P=czlock; PORT=18497; BASE=http://127.0.0.1:$PORT
TMP=$(mktemp -d)
export CZUJKA_VERSION=${CZUJKA_VERSION:-czlock} CZUJKA_PORT=$PORT CZUJKA_ADMIN_EMAIL=admin@czujka.local
export CZUJKA_ADMIN_PASSWORD="Lock-Admin-$RANDOM$RANDOM" CZUJKA_TRUST_PROXY=true
export CZUJKA_ALLOWED_NETWORKS="10.91.0.0/16, 127.0.0.1"
FAILS=0; PASSES=0
pass() { echo "  PASS  $1"; PASSES=$((PASSES + 1)); }
fail() { echo "  FAIL  $1"; FAILS=$((FAILS + 1)); }
check() { if [ "$2" = "$3" ]; then pass "$1: $2"; else fail "$1: got \"$2\", want \"$3\""; fi; }
dc() { docker compose -p $P -f deploy/docker-compose.yml "$@"; }
cleanup() { [ "${E2E_KEEP:-0}" = 1 ] || dc down -v --remove-orphans >/dev/null 2>&1; rm -rf "$TMP"; }
trap cleanup EXIT
# Every request comes "through the proxy": the client part of X-Forwarded-For
# is forged on purpose, the proxy part (rightmost) is fixed.
XFF="203.0.113.50"
CSRF=""; LCODE=""
login() { # email password [xff] -> sets LCODE (http status) and CSRF
  local x=${3:-$XFF}
  LCODE=$(curl -sS -o $TMP/login.json -w '%{http_code}' -c $TMP/jar -H "X-Forwarded-For: $x" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}" $BASE/api/v1/auth/login)
  CSRF=$(jq -r '.csrf_token // empty' $TMP/login.json 2>/dev/null)
}
api() { local d=(); [ -n "${3:-}" ] && d=(-d "$3"); curl -sS -b $TMP/jar -H "X-Forwarded-For: $XFF" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -X "$1" ${d[@]+"${d[@]}"} "$BASE/api/v1$2"; }
apicode() { local d=(); [ -n "${3:-}" ] && d=(-d "$3"); curl -sS -o $TMP/out.json -w '%{http_code}' -b $TMP/jar -H "X-Forwarded-For: $XFF" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -X "$1" ${d[@]+"${d[@]}"} "$BASE/api/v1$2"; }

echo "=== 1. Stack with CZUJKA_ALLOWED_NETWORKS=$CZUJKA_ALLOWED_NETWORKS ==="
dc up -d --build --wait 2>&1 | grep -E "Healthy|rror" || true
login $CZUJKA_ADMIN_EMAIL "$CZUJKA_ADMIN_PASSWORD"; check "admin login" "$LCODE" "200"

echo "=== 2. Operator lock ==="
check "the safety policy shows the lock" "$(api GET /settings/safety | jq -c .operator_networks)" '["10.91.0.0/16","127.0.0.1/32"]'
POL=$(api GET /settings/safety)
check "an administrator cannot widen the lock (allowed_networks 0.0.0.0/0)" "$(apicode PUT /settings/safety "$(echo "$POL" | jq -c '.allowed_networks = ["0.0.0.0/0"]')")" "422"
echo "  | $(jq -r .error.message $TMP/out.json | cut -c1-160)"
check "an administrator cannot drop the lock by sending operator_networks: []" "$(apicode PUT /settings/safety "$(echo "$POL" | jq -c '.operator_networks = []')") $(api GET /settings/safety | jq -c .operator_networks)" '200 ["10.91.0.0/16","127.0.0.1/32"]'
SC=$(api POST /scopes '{"name":"Blokada operatora"}' | jq -r .id)
R=$(api POST /scopes/$SC/targets '{"text":"8.8.8.0/24\n0.0.0.0/0\n10.91.1.0/24\n1.1.1.1"}')
check "a scope outside the lock is refused (saved targets)" "$(echo "$R" | jq -c '[.valid[].value]')" '["10.91.1.0/24"]'
check "every refused target names the operator lock" "$(echo "$R" | jq '[.invalid[] | select(.reason | contains("CZUJKA_ALLOWED_NETWORKS"))] | length')" "3"
echo "$R" | jq -r '.invalid[] | "  | \(.value): \(.reason)"'
check "the scope keeps only the target inside the lock" "$(api GET /scopes/$SC/targets | jq -c '[.items[].value]')" '["10.91.1.0/24"]'
PRJ=$(api POST /profiles "$(jq -nc --argjson s "$SC" '{name: "W blokadzie", scope_ids: [$s], ports: "80", enabled: true}')"); PR=$(echo "$PRJ" | jq -r .id)
check "a profile inside the lock is accepted" "$( [ "$PR" -gt 0 ] 2>/dev/null && echo ok || echo "$PRJ")" "ok"
CODE=$(apicode POST /runs/adhoc "$(jq -nc --argjson p "${PR:-0}" '{profile_id: $p, addresses: ["1.1.1.1"], ports: "80"}')")
check "an ad-hoc run outside the lock does not start (422 naming the lock)" "$CODE $(jq -r '.error.message | contains("CZUJKA_ALLOWED_NETWORKS")' $TMP/out.json)" "422 true"
echo "  | $(jq -r .error.message $TMP/out.json | cut -c1-200)"
check "no run was created by the refused requests" "$(api GET '/runs?limit=1' | jq .total)" "0"

echo "=== 3. Security headers ==="
for path in / /api/v1/healthz /api/v1/auth/me; do
  H=$(curl -sS -D - -o /dev/null $BASE$path | tr -d '\r')
  csp=$(echo "$H" | grep -i '^content-security-policy:' | cut -d' ' -f2-)
  ok=yes
  echo "$csp" | grep -q "frame-ancestors 'none'" || ok=no
  echo "$csp" | grep -q "default-src 'self'" || ok=no
  echo "$csp" | grep -q "script-src[^;]*unsafe-inline" && ok=no
  echo "$H" | grep -qi '^x-content-type-options: nosniff' || ok=no
  echo "$H" | grep -qi '^referrer-policy: no-referrer' || ok=no
  check "headers on $path (CSP without inline script, frame-ancestors none, nosniff, referrer)" "$ok" "yes"
done
echo "  | CSP: $csp"
check "the UI page has no inline script" "$(curl -sS $BASE/ | grep -o '<script[^>]*>' | grep -vc 'src=')" "0"
check "HSTS when the proxy says https" "$(curl -sS -D - -o /dev/null -H 'X-Forwarded-Proto: https' $BASE/api/v1/healthz | grep -ci '^strict-transport-security')" "1"

echo "=== 4. Login throttling behind the proxy ==="
# 25 wrong logins with a different forged client address each time: the
# proxy entry is the same, so the limit of 20 per minute per address holds.
codes=""
for i in $(seq 1 25); do login nikt@czujka.local "zle-haslo-$i" "10.0.0.$i, 198.51.100.7"; codes="$codes $LCODE"; done
check "a forged X-Forwarded-For does not bypass the per-address limit (429 after 20)" "$(echo $codes | tr ' ' '\n' | grep -c 429)" "5"
login $CZUJKA_ADMIN_EMAIL "$CZUJKA_ADMIN_PASSWORD" "198.51.100.8"; check "another client address is not blocked" "$LCODE" "200"
# Account lockout: 5 wrong passwords lock the account for 15 minutes, from any address.
for i in 1 2 3 4 5; do login $CZUJKA_ADMIN_EMAIL "zle-haslo-$i" "198.51.100.$((20 + i))"; done
login $CZUJKA_ADMIN_EMAIL "$CZUJKA_ADMIN_PASSWORD" "198.51.100.30"
check "the account is locked after 5 failures, also for the right password" "$LCODE $(jq -r .error.code $TMP/login.json)" "429 rate_limited"
check "the audit log has the client address from the proxy, not the forged one" "$(dc exec -T db psql -U czujka -d czujka -Atc "SELECT count(*) FROM audit_log WHERE ip LIKE '10.0.0.%'") $(dc exec -T db psql -U czujka -d czujka -Atc "SELECT count(*) > 0 FROM audit_log WHERE ip = '198.51.100.7'")" "0 t"

echo
echo "PASS: $PASSES  FAIL: $FAILS"
[ "$FAILS" -eq 0 ] && echo "LOCK/HARDENING OK" || exit 1
