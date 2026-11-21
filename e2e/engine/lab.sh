#!/usr/bin/env bash
# Starts or removes the engine test lab: docker network 10.77.0.0/22 with
# seven hosts at fixed addresses. All names carry the "czeng-" prefix.
# A second network, 10.78.0.0/24, and a router container (10.78.0.254 and
# 10.77.3.254) let the scanner reach the lab through a hop, like a campus
# network, instead of over one Ethernet segment. A third network,
# 10.79.0.0/20, is empty address space behind the same router.
#   ./lab.sh up     build the image, create the network and the hosts
#   ./lab.sh down   remove everything
set -euo pipefail
cd "$(dirname "$0")"
NET=czeng-net
SCANNET=czeng-scan
WIDENET=czeng-wide
IMG=czeng-lab:latest

down() {
  docker ps -aq --filter "name=^czeng-" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$NET" "$SCANNET" "$WIDENET" >/dev/null 2>&1 || true
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
  # router between the scanner network and the lab; it masquerades, so the
  # lab hosts need no return route
  docker network create --subnet 10.78.0.0/24 --gateway 10.78.0.1 "$SCANNET" >/dev/null
  docker run -d --name czeng-router --hostname router --network "$SCANNET" --ip 10.78.0.254 \
    --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 -e ROLE=router "$IMG" >/dev/null
  docker network connect --ip 10.77.3.254 "$NET" czeng-router
  # an empty /20 behind the router: 4096 addresses to show how the chunk groups grow
  docker network create --subnet 10.79.0.0/20 --gateway 10.79.0.1 "$WIDENET" >/dev/null
  docker network connect --ip 10.79.15.254 "$WIDENET" czeng-router
  sleep 2
  docker ps --filter "name=^czeng-" --format '{{.Names}}\t{{.Status}}' | sort
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
