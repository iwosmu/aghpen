#!/usr/bin/env bash
# Proof of the offline bundle: a fresh docker daemon (docker:dind) with no
# network at all (--network none) and no images loads the bundle and starts a
# healthy stack with install.sh. Nothing can be pulled, so the bundle must be
# complete. The container czbundle-dind is removed at the end.
#
#   ./deploy/e2e/bundle-proof.sh dist/czujka-bundle-<version>.tar.gz
set -uo pipefail
B=${1:?usage: bundle-proof.sh <bundle.tar.gz>}
B=$(cd "$(dirname "$B")" && pwd)/$(basename "$B")
N=czbundle-dind
FAILS=0; PASSES=0
pass() { echo "  PASS  $1"; PASSES=$((PASSES + 1)); }
fail() { echo "  FAIL  $1"; FAILS=$((FAILS + 1)); }
check() { if [ "$2" = "$3" ]; then pass "$1: $2"; else fail "$1: got \"$2\", want \"$3\""; fi; }
cleanup() { [ "${E2E_KEEP:-0}" = 1 ] || docker rm -f -v $N >/dev/null 2>&1; }
trap cleanup EXIT
inner() { docker exec $N sh -c "$1"; }

echo "=== 1. A clean docker daemon without network ==="
docker rm -f -v $N >/dev/null 2>&1 || true
docker run -d --name $N --privileged --network none -e DOCKER_TLS_CERTDIR= -v "$B:/bundle.tgz:ro" docker:28-dind >/dev/null
for i in $(seq 1 60); do inner 'docker info >/dev/null 2>&1' && break; sleep 1; done
check "the inner daemon has no images" "$(inner 'docker images -q | wc -l' | tr -d ' ')" "0"
check "the inner daemon has no network route out" "$(inner 'ip route | grep -c default' | tr -d ' ')" "0"
inner 'docker compose version'

echo "=== 2. install.sh from the bundle ==="
T0=$(date +%s)
inner 'mkdir -p /opt && tar -xzf /bundle.tgz -C /opt && cd /opt/czujka-bundle-* && CZUJKA_WRITE_SYSCTL=n sh install.sh' 2>&1 | grep -v -E "^ *(Container|Network|Volume) " | sed 's/^/  | /'
echo "  install took $(( $(date +%s) - T0 )) s (load + start)"
check "images loaded" "$(inner 'docker images --format "{{.Repository}}" | sort -u | tr "\n" " "')" "alpine czujka czujka-db "

echo "=== 3. The stack works ==="
HZ=$(inner 'wget -qO- http://127.0.0.1:8080/healthz')
echo "  healthz: $HZ" | cut -c1-220
check "healthz status" "$(echo "$HZ" | jq -r .status)" "ok"
check "pg_tde encrypts every table" "$(echo "$HZ" | jq -r .tde)" "true"
check "scan engine wired with nmap" "$(echo "$HZ" | jq -r '"\(.engine) \(.probe.mode)"')" "true nmap-raw"
EMAIL=$(inner 'cd /opt/czujka-bundle-* && grep ^CZUJKA_ADMIN_EMAIL= .env | cut -d= -f2-')
PW=$(inner 'cd /opt/czujka-bundle-* && grep ^CZUJKA_ADMIN_PASSWORD= .env | cut -d= -f2-')
LOGIN=$(inner "wget -qO- --header 'Content-Type: application/json' --post-data '{\"email\":\"$EMAIL\",\"password\":\"$PW\"}' http://127.0.0.1:8080/api/v1/auth/login")
check "the administrator from init.sh logs in" "$(echo "$LOGIN" | jq -r .user.role_slug)" "admin"
check "the UI is served" "$(inner 'wget -qO- http://127.0.0.1:8080/' | grep -c '<div id="root">')" "1"
check ".env written once with mode 600" "$(inner 'cd /opt/czujka-bundle-* && stat -c %a .env')" "600"

echo
echo "PASS: $PASSES  FAIL: $FAILS"
[ "$FAILS" -eq 0 ] && echo "BUNDLE OK" || exit 1
