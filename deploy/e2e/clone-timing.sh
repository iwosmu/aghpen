#!/usr/bin/env bash
# Time from git clone to a healthy stack, cold and warm.
#   cold: the czujka image is built with --no-cache (npm and Go modules are
#         downloaded again); the base images (node, golang, alpine) and the
#         database image czujka-db:17 are already local
#   warm: a second fresh clone, the build cache is warm
# Compose project czclone, port 127.0.0.1:18501; everything is removed after.
set -uo pipefail
SRC=$(cd "$(dirname "$0")/../.." && pwd)
D=$(mktemp -d)
export COMPOSE_PROJECT_NAME=czclone CZUJKA_VERSION=czclone CZUJKA_PORT=18501
dc() { docker compose -f deploy/docker-compose.yml "$@"; }
cleanup() { (cd "$D/a" 2>/dev/null && dc down -v --remove-orphans >/dev/null 2>&1); (cd "$D/b" 2>/dev/null && dc down -v --remove-orphans >/dev/null 2>&1); rm -rf "$D"; }
trap cleanup EXIT
one() { # dir build-flags
  local dir=$1 flags=$2 t0 t1 t2
  t0=$(date +%s)
  git clone -q "$SRC" "$D/$dir" && cd "$D/$dir" || return 1
  make -s init >/dev/null
  t1=$(date +%s)
  dc build $flags czujka >/dev/null 2>&1 || { echo "build failed"; return 1; }
  docker image inspect czujka-db:17 >/dev/null 2>&1 || docker build -q -t czujka-db:17 deploy/db >/dev/null
  dc up -d --no-build --wait >/dev/null 2>&1 || { echo "up failed"; dc ps; return 1; }
  t2=$(date +%s)
  echo "$dir: clone+init $((t1 - t0)) s, build+start $((t2 - t1)) s, total $((t2 - t0)) s; healthz: $(curl -sS http://127.0.0.1:18501/healthz | jq -c '{status, tde, engine}')"
  dc down -v --remove-orphans >/dev/null 2>&1
  cd "$SRC"
}
echo "commit $(git -C "$SRC" rev-parse --short HEAD); docker $(docker version --format '{{.Server.Version}}'), $(docker info --format '{{.NCPU}} CPU, {{.MemTotal}} B RAM' 2>/dev/null)"
one a "--no-cache"
one b ""
