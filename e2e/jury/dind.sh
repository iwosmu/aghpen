#!/usr/bin/env bash
# A fresh "jury machine": one docker:dind container in which both the organisers' template (lab/jury) and Czujka run,
# so the docker host that Czujka scans (host.docker.internal = the dind gateway) is a throwaway container and nothing
# else is reachable with the template ports. This is the Linux reproduction of what the jury does: template stacks on
# one docker host, Czujka from deploy/docker-compose.yml next to them. Then e2e/jury/run.sh runs inside it and its output
# is written to e2e/jury/transcript.txt.
#
#   e2e/jury/dind.sh                 (about 40 minutes: image transfer, then six stacks and the change scenarios)
#
# Only Czujka's UI is published to this machine: http://127.0.0.1:$JURY_UI_PORT (default 18720). JURY_KEEP=1 keeps the
# container afterwards; JURY_ONLY limits the stages of run.sh. Images: Czujka is built here from the working tree;
# template images are copied from the local docker cache when present, else pulled inside.
set -uo pipefail
cd "$(dirname "$0")/../.."
N=czjury-dind
UI=${JURY_UI_PORT:-18720}
TAG=${CZUJKA_VERSION:-jury}
PW="Jury-$(date +%s)-$RANDOM$RANDOM"
OUT=e2e/jury/transcript.txt
log() { echo "[$(date +%H:%M:%S)] $*"; }
inner() { docker exec "$N" sh -c "$1"; }
cleanup() { [ "${JURY_KEEP:-0}" = 1 ] || docker rm -f -v "$N" >/dev/null 2>&1; }
trap cleanup EXIT

log "building Czujka (czujka:$TAG) from the working tree"
CZUJKA_VERSION=$TAG docker compose -f deploy/docker-compose.yml build -q || exit 1

log "starting the jury machine $N (docker:28-dind)"
docker rm -f -v "$N" >/dev/null 2>&1 || true
docker run -d --name "$N" --privileged -e DOCKER_TLS_CERTDIR= -p "127.0.0.1:$UI:18080" docker:28-dind >/dev/null || exit 1
for i in $(seq 1 60); do inner 'docker info >/dev/null 2>&1' && break; sleep 1; done
inner 'apk add -q --no-cache bash curl jq >/dev/null' || exit 1
# COPYFILE_DISABLE and the exclude keep macOS AppleDouble files (._*) out: Traefik's file provider fails on them.
COPYFILE_DISABLE=1 tar --exclude='._*' -c deploy lab/jury e2e/jury | docker exec -i "$N" sh -c 'mkdir -p /work && tar -x -C /work'

log "copying images into the jury machine"
docker image inspect alpine:3.22 >/dev/null 2>&1 || docker pull -q alpine:3.22 >/dev/null
docker save "czujka:$TAG" czujka-db:17 alpine:3.22 | docker exec -i "$N" docker load -q
IMAGES=$(for f in lab/jury/docker-compose-*.yml e2e/jury/compose/*.yml; do docker compose --env-file e2e/jury/env/proxy-base.env -f "$f" config --images 2>/dev/null; done | sort -u)
for img in $IMAGES; do
  if docker image inspect "$img" >/dev/null 2>&1 && docker save "$img" | docker exec -i "$N" docker load -q >/dev/null 2>&1; then echo "  copied $img"
  else echo "  pulling $img inside"; inner "docker pull -q $img >/dev/null 2>&1 || DOCKER_DEFAULT_PLATFORM=linux/amd64 docker pull -q $img >/dev/null"; fi
done

GW=$(inner "docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}'")
HIP=${JURY_HOST_IP:-172.31.250.10}
log "starting Czujka inside; operator lock CZUJKA_ALLOWED_NETWORKS=$GW/32,$HIP/32 (the jury machine itself and the second test host)"
inner "cd /work && CZUJKA_VERSION=$TAG CZUJKA_BIND=0.0.0.0 CZUJKA_PORT=18080 CZUJKA_ADMIN_PASSWORD='$PW' CZUJKA_ALLOWED_NETWORKS=$GW/32,$HIP/32 \
  docker compose -p czujka -f deploy/docker-compose.yml up -d --no-build --wait 2>&1 | tail -2" || exit 1
log "Czujka UI: http://127.0.0.1:$UI (admin@czujka.local; the password is printed only to this terminal: $PW)"

docker exec -e CZ_URL=http://127.0.0.1:18080 -e CZ_PASSWORD="$PW" -e JURY_TARGET="${JURY_TARGET:-localhost}" -e JURY_GUARD=0 -e JURY_HOST_IP="$HIP" -e JURY_ONLY="${JURY_ONLY:-}" "$N" \
  bash -c 'cd /work && [ -n "$JURY_ONLY" ] || unset JURY_ONLY; bash e2e/jury/run.sh' 2>&1 | sed "s/$PW/<hasło>/g" | tee "$OUT"
RC=${PIPESTATUS[0]}
log "transcript: $OUT (exit $RC)"
exit "$RC"
