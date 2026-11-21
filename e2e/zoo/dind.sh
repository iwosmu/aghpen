#!/usr/bin/env bash
# The "zoo machine": one docker:dind container in which the zoo services and Czujka run (the same pattern as
# e2e/jury/dind.sh). Czujka scans target "localhost" = the docker host of this machine (the dind container itself);
# the operator lock CZUJKA_ALLOWED_NETWORKS is that gateway /32, so no scan leaves the machine. Only Czujka's UI is
# published, on 127.0.0.1:$ZOO_UI_PORT. Never run run.sh against a real docker host (e.g. a laptop): use this script.
#
#   e2e/zoo/pull.sh                            (once: pull every zoo image into the local docker cache)
#   ZOO_PHASE=before e2e/zoo/dind.sh [batch ...]   (default: every batch; results in e2e/zoo/out/$ZOO_PHASE/<batch>)
#   go run ./e2e/zoo/score -phase before       (score them)
#
# ZOO_NMAP=1 also runs plain nmap -sV per batch. ZOO_KEEP=1 keeps the machine. CZUJKA_VERSION names the image built here.
set -uo pipefail
cd "$(dirname "$0")/../.."
N=czzoo-dind
UI=${ZOO_UI_PORT:-18740}
TAG=${CZUJKA_VERSION:-zoo}
PHASE=${ZOO_PHASE:-before}
PW="Zoo-$(date +%s)-$RANDOM$RANDOM"
BATCHES=${*:-$(ls e2e/zoo/batches | sed 's/\.yml$//')}
log() { echo "[$(date +%H:%M:%S)] $*"; }
inner() { docker exec "$N" sh -c "$1"; }
cleanup() { [ "${ZOO_KEEP:-0}" = 1 ] || docker rm -f -v "$N" >/dev/null 2>&1; }
trap cleanup EXIT

if [ "${ZOO_NOBUILD:-0}" != 1 ]; then
  log "building Czujka (czujka:$TAG) from the working tree at $(git rev-parse --short HEAD)$(git diff --quiet -- . ':!e2e' || echo ' with local changes')"
  CZUJKA_VERSION=$TAG docker compose -f deploy/docker-compose.yml build -q || exit 1
fi

log "starting the zoo machine $N (docker:28-dind)"
docker rm -f -v "$N" >/dev/null 2>&1 || true
docker run -d --name "$N" --privileged -e DOCKER_TLS_CERTDIR= -p "127.0.0.1:$UI:18080" docker:28-dind >/dev/null || exit 1
for i in $(seq 1 60); do inner 'docker info >/dev/null 2>&1' && break; sleep 1; done
inner 'apk add -q --no-cache bash curl jq >/dev/null' || exit 1
COPYFILE_DISABLE=1 tar --exclude='._*' --exclude='e2e/zoo/out' -c deploy e2e/zoo | docker exec -i "$N" sh -c 'mkdir -p /work && tar -x -C /work'
docker image inspect alpine:3.22 >/dev/null 2>&1 || docker pull -q alpine:3.22 >/dev/null
docker save "czujka:$TAG" czujka-db:17 alpine:3.22 | docker exec -i "$N" docker load -q >/dev/null

GW=$(inner "docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}'")
log "starting Czujka inside; operator lock CZUJKA_ALLOWED_NETWORKS=$GW/32"
inner "cd /work && CZUJKA_VERSION=$TAG CZUJKA_BIND=0.0.0.0 CZUJKA_PORT=18080 CZUJKA_ADMIN_PASSWORD='$PW' CZUJKA_ALLOWED_NETWORKS=$GW/32 \
  docker compose -p czujka -f deploy/docker-compose.yml up -d --no-build --wait 2>&1 | tail -1" || exit 1
log "Czujka UI: http://127.0.0.1:$UI (admin@czujka.local / $PW)"
mkdir -p e2e/zoo/out
echo "czujka $(inner 'curl -s http://127.0.0.1:18080/healthz') code $(git rev-parse --short HEAD)" | tee "e2e/zoo/out/$PHASE.version" 2>/dev/null || true

for b in $BATCHES; do
  e2e/zoo/pull.sh "$b" | grep -v '^cached' || true
  imgs=$(docker compose -f "e2e/zoo/batches/$b.yml" config --images | sort -u)
  for img in $imgs; do
    inner "docker image inspect $img >/dev/null 2>&1" && continue
    docker save "$img" | docker exec -i "$N" docker load -q >/dev/null 2>&1 || inner "docker pull -q $img >/dev/null 2>&1 || DOCKER_DEFAULT_PLATFORM=linux/amd64 docker pull -q $img >/dev/null"
  done
  # the zoo files may have changed since the machine started (truth.tsv edits between batches)
  COPYFILE_DISABLE=1 tar --exclude='._*' --exclude='e2e/zoo/out' -c e2e/zoo | docker exec -i "$N" sh -c 'tar -x -C /work'
  docker exec -e CZ_URL=http://127.0.0.1:18080 -e CZ_PASSWORD="$PW" -e ZOO_GW="$GW" -e ZOO_KEEP_BATCH="${ZOO_KEEP_BATCH:-0}" "$N" \
    bash -c "cd /work && bash e2e/zoo/run.sh $b /work/out/$b ${ZOO_NMAP:+nmap}" 2>&1 | sed "s/$PW/<hasło>/g"
  rm -rf "e2e/zoo/out/$PHASE/$b"; mkdir -p "e2e/zoo/out/$PHASE"
  docker cp "$N:/work/out/$b" "e2e/zoo/out/$PHASE/$b" >/dev/null
  # free the machine's disk: drop this batch's images (Czujka's stay)
  [ "${ZOO_KEEP_BATCH:-0}" = 1 ] || inner "docker image rm -f $(echo $imgs | tr '\n' ' ') >/dev/null 2>&1; true"
done
log "results: e2e/zoo/out/$PHASE"
