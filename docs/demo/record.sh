#!/usr/bin/env bash
# Re-records the demo film in one command.
#
#   CZ_URL=https://... CZ_EMAIL=... CZ_PASS=... [CZ_STOP=0] docs/demo/record.sh
#
# Credentials come from the environment only. Nothing here or in record.mjs prints or stores them; the sign-in on CZ_URL
# happens off camera and the account block is blurred in every frame.
#
# 1. starts a throwaway fresh stack "czpwiz" (port 18641, image czujka:${CZUJKA_VERSION:-czpitch}) for the
#    install-and-wizard shot and reads its first-run password from the log (built from this checkout when missing);
# 2. runs docs/demo/record.mjs against CZ_URL (all CZ_* variables pass through, see the header of record.mjs);
# 3. removes the throwaway stack.
# CZ_NO_WIZARD=1 skips the fresh stack (shot 1 then shows the login on CZ_URL).
# Output: docs/demo/czujka-demo.mp4, czujka-demo.pl.srt, lektor.txt.
set -euo pipefail
cd "$(dirname "$0")"
DEMO=$(pwd)
ROOT=$(cd ../.. && pwd)
[ -n "${CZ_PASS:-${CZ_PASSWORD:-}}" ] || { echo "set CZ_PASS (and CZ_URL, CZ_EMAIL when the stack is not the local one)"; exit 2; }
[ -d node_modules/playwright ] || npm install --no-audit --no-fund
npx playwright install chromium-headless-shell >/dev/null

if [ "${CZ_NO_WIZARD:-0}" != 1 ]; then
  WIZ="docker compose -p czpwiz -f $ROOT/deploy/docker-compose.yml"
  export CZUJKA_VERSION=${CZUJKA_VERSION:-czpitch} CZUJKA_PORT=${CZ_WIZARD_PORT:-18641}
  docker image inspect "czujka:$CZUJKA_VERSION" >/dev/null 2>&1 || $WIZ build -q
  $WIZ down -v >/dev/null 2>&1 || true
  trap '$WIZ down -v >/dev/null 2>&1 || true' EXIT
  $WIZ up -d --wait
  for _ in $(seq 1 30); do
    CZ_WIZARD_PASSWORD=$(docker logs czpwiz-czujka-1 2>&1 | awk '/first administrator created/ {f=1} f && /password:/ {print $2; exit}')
    [ -n "$CZ_WIZARD_PASSWORD" ] && break; sleep 1
  done
  export CZ_WIZARD_URL=http://127.0.0.1:$CZUJKA_PORT CZ_WIZARD_PASSWORD
fi
node "$DEMO/record.mjs"
