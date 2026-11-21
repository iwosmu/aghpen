#!/usr/bin/env bash
# Starts or removes the engine test lab: docker network 10.77.0.0/22 with
# seven hosts at fixed addresses. All names carry the "czeng-" prefix.
#   ./lab.sh up     build the image, create the network and the hosts
#   ./lab.sh down   remove everything
set -euo pipefail
cd "$(dirname "$0")"
NET=czeng-net
IMG=czeng-lab:latest

down() {
  docker ps -aq --filter "name=^czeng-" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}

up() {
  down
  docker build -q -t "$IMG" lab >/dev/null
  docker network create --subnet 10.77.0.0/22 --gateway 10.77.0.1 "$NET" >/dev/null
  run() { # name ip [docker args...] -- image [cmd...]
    local name=$1 ip=$2; shift 2
    docker run -d --name "czeng-$name" --hostname "$name" --network "$NET" --ip "$ip" "$@" >/dev/null
  }
  run nginx   10.77.0.10 nginx:alpine
  run ssh     10.77.0.20 -e ROLE=ssh "$IMG"
  run redis   10.77.1.30 redis:7-alpine
  run http-a  10.77.2.40 -e ROLE=http  -e PORT=8765 "$IMG"
  run http-b  10.77.2.41 -e ROLE=http  -e PORT=8081 "$IMG"
  run https   10.77.3.50 -e ROLE=https -e PORT=9443 "$IMG"
  run noicmp  10.77.3.60 --cap-add NET_ADMIN -e ROLE=noicmp -e PORT=80 "$IMG"
  sleep 2
  docker ps --filter "name=^czeng-" --format '{{.Names}}\t{{.Status}}' | sort
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
