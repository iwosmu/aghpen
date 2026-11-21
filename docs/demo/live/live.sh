#!/usr/bin/env bash
# Live showcase kit: one "jury machine" (docker:28-dind) with Czujka and the organisers' template inside.
# Only Czujka's UI leaves the machine: http://127.0.0.1:${LIVE_UI_PORT:-18730}. Nothing is scanned outside it:
# the operator lock (CZUJKA_ALLOWED_NETWORKS) is the machine's own bridge gateway and one test host.
#
#   docs/demo/live/live.sh prewarm     build and pull every image (run with Internet, before the event)
#   docs/demo/live/live.sh start       start the machine (about 2 minutes), print the admin password once
#   docs/demo/live/live.sh 1 .. 7      reset Czujka in the machine and prepare case N (docs/demo/LIVE.md)
#   docs/demo/live/live.sh 1 change    the live step of a case (each case lists its steps: live.sh N help)
#   docs/demo/live/live.sh reset       empty Czujka (new database, same admin password), all stacks down
#   docs/demo/live/live.sh stop        remove the machine
set -uo pipefail
cd "$(dirname "$0")/../../.."
N=czlive
UI=${LIVE_UI_PORT:-18730}
TAG=${CZUJKA_VERSION:-live}
HIP=172.31.250.10
log() { echo "[$(date +%H:%M:%S)] $*"; }
inner() { docker exec "$N" sh -c "$1"; }
running() { [ "$(docker inspect -f '{{.State.Running}}' "$N" 2>/dev/null)" = true ]; }

images() { # every image the machine needs
  for f in lab/jury/docker-compose-*.yml e2e/jury/compose/*.yml lab/defectdojo/docker-compose.yml; do
    docker compose --env-file e2e/jury/env/proxy-base.env -f "$f" config --images 2>/dev/null
  done | sort -u
  echo alpine:3.22
}

case "${1:-help}" in
prewarm)
  log "building Czujka (czujka:$TAG) from this checkout"
  CZUJKA_VERSION=$TAG docker compose -f deploy/docker-compose.yml build -q || exit 1
  printf 'FROM docker:28-dind\nRUN apk add --no-cache bash curl jq\n' | docker build -q -t czujka-live-machine - >/dev/null || exit 1
  for img in $(images); do
    if docker image inspect "$img" >/dev/null 2>&1; then echo "  have  $img"
    else echo "  pull  $img"; docker pull -q "$img" >/dev/null 2>&1 || docker pull -q --platform linux/amd64 "$img" >/dev/null || exit 1; fi
  done
  log "all images are local: the event needs no Internet" ;;
start)
  t0=$(date +%s)
  CZUJKA_VERSION=$TAG docker compose -f deploy/docker-compose.yml build -q || exit 1
  docker rm -f -v "$N" >/dev/null 2>&1 || true
  docker image inspect czujka-live-machine >/dev/null 2>&1 || { echo "run docs/demo/live/live.sh prewarm first (with Internet)"; exit 1; }
  docker run -d --name "$N" --privileged -e DOCKER_TLS_CERTDIR= -p "127.0.0.1:$UI:18080" czujka-live-machine >/dev/null || exit 1
  for i in $(seq 1 60); do inner 'docker info >/dev/null 2>&1' && break; sleep 1; done
  COPYFILE_DISABLE=1 tar --exclude='._*' -c deploy lab/jury lab/defectdojo e2e/jury docs/demo/live | docker exec -i "$N" sh -c 'mkdir -p /work && tar -x -C /work'
  log "copying images into the machine"
  docker save "czujka:$TAG" czujka-db:17 | docker exec -i "$N" docker load -q >/dev/null
  for img in $(images); do docker save "$img" 2>/dev/null | docker exec -i "$N" docker load -q >/dev/null 2>&1 || echo "  missing $img (run live.sh prewarm)"; done
  GW=$(inner "docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}'")
  PW="Live-$(date +%s)-$RANDOM$RANDOM"
  printf 'TAG=%s\nGW=%s\nHIP=%s\nPW=%s\n' "$TAG" "$GW" "$HIP" "$PW" | docker exec -i "$N" sh -c 'cat > /work/.live && chmod 600 /work/.live'
  docker exec "$N" bash /work/docs/demo/live/inner.sh czujka_up || exit 1
  log "ready in $(( $(date +%s) - t0 )) s: http://127.0.0.1:$UI  login admin@czujka.local  password $PW (shown only here)" ;;
stop) docker rm -f -v "$N" >/dev/null 2>&1; log "machine removed" ;;
pass) running && docker exec "$N" sh -c '. /work/.live; echo "admin@czujka.local $PW"' ;;
help|-h|--help) sed -n 2,14p "$0" ;;
*)
  running || { echo "the machine is not running: docs/demo/live/live.sh start"; exit 1; }
  # keep the scripts in the machine in step with this checkout
  COPYFILE_DISABLE=1 tar --exclude='._*' -c docs/demo/live e2e/jury | docker exec -i "$N" sh -c 'tar -x -C /work'
  cmd=$1; shift; case $cmd in [1-7]) cmd=c$cmd ;; reset|run|changes_after) ;; *) echo "unknown command: $cmd (live.sh help)"; exit 2 ;; esac
  docker exec -e LIVE_UI="http://127.0.0.1:$UI" "$N" bash /work/docs/demo/live/inner.sh "$cmd" "$@" ;;
esac
