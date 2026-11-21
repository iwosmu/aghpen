#!/usr/bin/env bash
# Captures real responses for signature test data (signatures/testdata/zoo) from a zoo image: starts it inside the zoo
# machine on a private docker network with no published port (so a running zoo scan never sees it), GETs the given
# paths from the zoo machine and prints them. GET only, no credentials.
#   e2e/zoo/capture.sh <image> <container-port> <path> [path ...] [-- docker run args / command]
set -uo pipefail
N=${ZOO_MACHINE:-czzoo-dind}
img=$1; port=$2; shift 2
paths=(); while [ $# -gt 0 ] && [ "$1" != -- ]; do paths+=("$1"); shift; done; [ "${1:-}" = -- ] && shift
docker exec "$N" docker image inspect "$img" >/dev/null 2>&1 || docker save "$img" | docker exec -i "$N" docker load -q >/dev/null
docker exec "$N" sh -c 'docker network inspect zoocap >/dev/null 2>&1 || docker network create --internal zoocap >/dev/null'
c=zoocap-$RANDOM
docker exec "$N" docker run -d --name "$c" --network zoocap "$@" "$img" ${ZOO_CMD:-} >/dev/null
ip=$(docker exec "$N" docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$c")
for i in $(seq 1 ${ZOO_WAIT:-60}); do docker exec "$N" curl -s -m 3 -o /dev/null "http://$ip:$port/" && break; sleep 2; done
sleep ${ZOO_SETTLE:-3}
for p in "${paths[@]}"; do
  echo "=== GET $p"
  docker exec "$N" curl -s -m 10 -D - "http://$ip:$port$p"
  echo
done
docker exec "$N" docker rm -f "$c" >/dev/null
