#!/usr/bin/env bash
# Pulls every zoo image into the local docker cache (the docker host of this machine), so that e2e/zoo/dind.sh can copy
# them into the zoo machine without pulling there. Images without an arm64 build are pulled for linux/amd64.
#   e2e/zoo/pull.sh [batch ...]        (default: every batch under e2e/zoo/batches)
set -uo pipefail
cd "$(dirname "$0")/../.."
B=${*:-$(ls e2e/zoo/batches | sed 's/\.yml$//')}
imgs=$(for b in $B; do docker compose -f "e2e/zoo/batches/$b.yml" config --images; done | sort -u)
pull() { docker image inspect "$1" >/dev/null 2>&1 && { echo "cached $1"; return; }
  docker pull -q "$1" >/dev/null 2>&1 && { echo "pulled $1"; return; }
  docker pull -q --platform linux/amd64 "$1" >/dev/null 2>&1 && { echo "pulled $1 (linux/amd64)"; return; }
  echo "FAILED $1"; }
export -f pull
printf '%s\n' $imgs | xargs -P 4 -I{} bash -c 'pull {}'
