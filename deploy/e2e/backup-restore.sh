#!/usr/bin/env bash
# Proof of czujka backup / czujka restore on a clean stack.
#
#   ./deploy/e2e/backup-restore.sh          build, prove, remove everything it created
#   E2E_KEEP=1 ./deploy/e2e/backup-restore.sh   keep both stacks
#
# Stack A gets real data through the API (scope, manual host, nmap import,
# findings, DefectDojo API key). "czujka backup" writes one encrypted archive.
# Stack B starts empty with its own volumes and the same master key; "czujka
# restore" loads the archive; the API of B then shows the data of A, the users
# of A can log in, pg_tde encrypts every table and the key opens the
# encrypted fields. A restore with another master key is refused.
# It scans nothing. Ports: 127.0.0.1:18495 (A) and 18496 (B).
set -uo pipefail
cd "$(dirname "$0")/../.."
TMP=$(mktemp -d); chmod 755 "$TMP"
A=czbk-a; B=czbk-b
export CZUJKA_VERSION=${CZUJKA_VERSION:-czbk} CZUJKA_ADMIN_EMAIL=admin@czujka.local
PW_A="Backup-A-$RANDOM$RANDOM"; PW_B="Backup-B-$RANDOM$RANDOM"
FAILS=0; PASSES=0
pass() { echo "  PASS  $1"; PASSES=$((PASSES + 1)); }
fail() { echo "  FAIL  $1"; FAILS=$((FAILS + 1)); }
check() { if [ "$2" = "$3" ]; then pass "$1: $2"; else fail "$1: got \"$2\", want \"$3\""; fi; }
dc() { local p=$1; shift; docker compose -p "$p" -f deploy/docker-compose.yml "$@"; }
cleanup() {
  if [ "${E2E_KEEP:-0}" != 1 ]; then dc $A down -v --remove-orphans >/dev/null 2>&1; dc $B down -v --remove-orphans >/dev/null 2>&1; fi
  rm -rf "$TMP"
}
trap cleanup EXIT
login() { # base email password -> sets CSRF and the cookie jar $TMP/jar.<port>
  JAR=$TMP/jar.$2; CSRF=$(curl -sS -c "$JAR" -H 'Content-Type: application/json' -d "{\"email\":\"$CZUJKA_ADMIN_EMAIL\",\"password\":\"$3\"}" "$1/api/v1/auth/login" | jq -r .csrf_token)
}
api() { curl -sS -b "$JAR" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -X "$1" ${3:+-d "$3"} "$BASE/api/v1$2"; }
snapshot() { # one line with the data the restore must keep
  echo "hosts=$(api GET '/hosts?limit=1' | jq .total) services=$(api GET '/services?limit=1' | jq .total) findings=$(api GET '/findings?limit=1' | jq .total) runs=$(api GET '/runs?limit=1' | jq .total) scopes=$(api GET '/scopes?limit=1' | jq .total) dojo_key=$(api GET /settings/defectdojo | jq -r .api_key_set) manual=$(api GET '/hosts?q=10.77.0.9' | jq -r '.items[0].hostnames | join(",")')"
}

echo "=== 1. Stack A: build and start ==="
T0=$(date +%s)
CZUJKA_PORT=18495 CZUJKA_ADMIN_PASSWORD=$PW_A dc $A up -d --build --wait 2>&1 | grep -E "Healthy|rror" || true
echo "  stack A healthy after $(( $(date +%s) - T0 )) s"
BASE=http://127.0.0.1:18495; login $BASE 18495 "$PW_A"
check "stack A login" "$( [ -n "$CSRF" ] && [ "$CSRF" != null ] && echo ok)" "ok"

echo "=== 2. Real data in A through the API ==="
SC=$(api POST /scopes '{"name":"Kopia zapasowa","description":"dane do odtworzenia"}' | jq -r .id)
api POST /scopes/$SC/targets '{"text":"10.77.0.0/24"}' >/dev/null
api POST /hosts '{"ip":"10.77.0.9","hostnames":["reczny.backup.test"],"services":[{"port":8443,"name":"https","product":"Jetty","tls":true,"title":"Panel zapasowy","banner":"tajny-baner-kopii"}]}' >/dev/null
cat > $TMP/scan.xml <<'EOF'
<?xml version="1.0"?><nmaprun scanner="nmap" start="1700000000"><host><status state="up" reason="syn-ack"/><address addr="10.77.0.20" addrtype="ipv4"/><ports><port protocol="tcp" portid="6379"><state state="open" reason="syn-ack"/><service name="redis" product="Redis key-value store" version="7.2.4"/></port><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="9.6"/></port></ports></host><runstats><finished time="1700000100"/></runstats></nmaprun>
EOF
curl -sS -b "$JAR" -H "X-CSRF-Token: $CSRF" -F "file=@$TMP/scan.xml" -F "scope_id=$SC" "$BASE/api/v1/import/results" | jq -c '{run_id, hosts, services}'
api PUT /settings/defectdojo '{"url":"http://dojo.invalid:8080","api_key":"tajny-klucz-dojo-123","enabled":false}' >/dev/null
api POST /findings '{"title":"Ręczna obserwacja kopii","severity":"high","ip":"10.77.0.20","port":6379,"description":"do odtworzenia"}' >/dev/null
SNAP_A=$(snapshot); echo "  A: $SNAP_A"

echo "=== 3. czujka backup in A ==="
dc $A exec -T czujka czujka backup -o /var/lib/czujka/backups/a.czbk
dc $A cp czujka:/var/lib/czujka/backups/a.czbk $TMP/a.czbk
KEY_A=$(dc $A exec -T czujka cat /var/lib/czujka/master.key | tr -d '\r\n')
ls -l $TMP/a.czbk | awk '{print "  archive: " $5 " bytes"}'
check "archive starts with the Czujka magic line" "$(head -1 $TMP/a.czbk)" "CZUJKA-BACKUP v1"
check "archive has no clear text (hostname, banner, DefectDojo key)" "$(grep -c -a -e reczny.backup.test -e tajny-baner -e tajny-klucz-dojo $TMP/a.czbk)" "0"
chmod 644 $TMP/a.czbk

echo "=== 4. Stack B: clean volumes, same master key ==="
T0=$(date +%s)
CZUJKA_PORT=18496 CZUJKA_ADMIN_PASSWORD=$PW_B CZUJKA_MASTER_KEY=$KEY_A dc $B up -d --wait 2>&1 | grep -E "Healthy|rror" || true
echo "  stack B healthy after $(( $(date +%s) - T0 )) s"
BASE=http://127.0.0.1:18496; login $BASE 18496 "$PW_B"
check "B starts empty" "$(api GET '/hosts?limit=1' | jq .total)" "0"

echo "=== 5. Restore with another master key is refused ==="
OTHER=$(dc $B run --rm --no-deps -T czujka genkey | tr -d '\r\n')
if CZUJKA_PORT=18496 CZUJKA_MASTER_KEY=$OTHER dc $B run --rm --no-deps -T -v "$TMP:/backup:ro" czujka restore -i /backup/a.czbk --force > $TMP/wrong.txt 2>&1; then
  fail "restore with another master key must fail"
else
  check "restore with another master key refused (key mismatch)" "$(grep -c 'another master key' $TMP/wrong.txt)" "1"
  grep -m1 'czujka:' $TMP/wrong.txt | cut -c1-160 | sed 's/^/  | /'
fi
check "B is unchanged after the refused restore" "$(api GET '/scopes?limit=1' | jq .total)" "0"

echo "=== 6. czujka restore in B ==="
CZUJKA_PORT=18496 CZUJKA_MASTER_KEY=$KEY_A dc $B stop czujka >/dev/null
T0=$(date +%s)
CZUJKA_PORT=18496 CZUJKA_MASTER_KEY=$KEY_A dc $B run --rm --no-deps -T -v "$TMP:/backup:ro" czujka restore -i /backup/a.czbk --force 2>&1 | sed 's/^/  | /'
RC=${PIPESTATUS[0]}
check "restore exit code" "$RC" "0"
echo "  restore took $(( $(date +%s) - T0 )) s"
CZUJKA_PORT=18496 CZUJKA_MASTER_KEY=$KEY_A dc $B start czujka >/dev/null
for i in $(seq 1 60); do [ "$(docker inspect -f '{{.State.Health.Status}}' $B-czujka-1)" = healthy ] && break; sleep 2; done

echo "=== 7. B shows the data of A ==="
login $BASE 18496 "$PW_A"
check "the administrator of A logs in to B (users restored)" "$( [ -n "$CSRF" ] && [ "$CSRF" != null ] && echo ok)" "ok"
SNAP_B=$(snapshot); echo "  B: $SNAP_B"
check "data of A in B" "$SNAP_B" "$SNAP_A"
HZ=$(curl -sS -b "$JAR" $BASE/healthz)
check "pg_tde encrypts the restored tables" "$(echo "$HZ" | jq -r .tde)" "true"
DOC=$(CZUJKA_PORT=18496 CZUJKA_MASTER_KEY=$KEY_A dc $B exec -T czujka czujka doctor --json)
check "doctor in B: database, pg_tde and master key" "$(echo "$DOC" | jq -r '[.checks[] | select(.name == "database" or .name == "pg_tde" or .name == "master_key") | .status] | join(",")')" "ok,ok,ok"
echo "$DOC" | jq -r '.checks[] | "  doctor: [\(.status)] \(.title): \(.detail)"'

echo
echo "PASS: $PASSES  FAIL: $FAILS"
[ "$FAILS" -eq 0 ] && echo "BACKUP/RESTORE OK" || exit 1
