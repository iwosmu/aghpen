#!/usr/bin/env bash
# Target network of the full end-to-end check: docker network 10.91.0.0/22
# with real services. Every name carries the "czfull-" prefix; nothing else is
# touched. The role image is the engine lab image (e2e/engine/lab).
#   ./lab.sh up       create the network and the hosts (state 1)
#   ./lab.sh change   state 2: stop redis, add a new nginx host, upgrade nginx, change one page title
#   ./lab.sh down     remove everything
set -euo pipefail
cd "$(dirname "$0")"
NET=${LAB_NET:-czfull-net}
SUBNET=${LAB_SUBNET:-10.91.0.0/22}
P=${LAB_PREFIX:-10.91}
IMG=czfull-lab:latest

down() {
  docker ps -aq --filter "name=^czfull-lab-" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}

run() { # name ip [docker args...] image [cmd...]
  local name=$1 ip=$2; shift 2
  docker run -d --name "czfull-lab-$name" --hostname "$name" --network "$NET" --ip "$ip" "$@" >/dev/null
}

up() {
  down
  docker build -q -t "$IMG" ../engine/lab >/dev/null
  docker network create --subnet "$SUBNET" --gateway "$P.0.1" "$NET" >/dev/null
  run nginx     "$P.0.10" nginx:1.24.0-alpine
  run ssh       "$P.0.20" -e ROLE=ssh "$IMG"
  run redis     "$P.1.30" redis:7-alpine
  run mariadb   "$P.1.81" -e MARIADB_ROOT_PASSWORD=lab-root -e MARIADB_DATABASE=wp -e MARIADB_USER=wp -e MARIADB_PASSWORD=lab-wp mariadb:11
  run wordpress "$P.1.80" -e WORDPRESS_DB_HOST="$P.1.81" -e WORDPRESS_DB_USER=wp -e WORDPRESS_DB_PASSWORD=lab-wp -e WORDPRESS_DB_NAME=wp wordpress:6.9.4-php8.3-apache
  run http-a    "$P.2.40" -e ROLE=http -e PORT=8765 "$IMG"
  run grafana   "$P.2.90" grafana/grafana:12.4.15
  run https     "$P.3.50" -e ROLE=https -e PORT=9443 "$IMG"
  run noicmp    "$P.3.60" --cap-add NET_ADMIN -e ROLE=noicmp -e PORT=80 "$IMG"
  # wait until the web apps answer (WordPress needs its database)
  for i in $(seq 1 90); do
    if docker exec czfull-lab-wordpress sh -c 'curl -fsS -o /dev/null -w "%{http_code}" http://127.0.0.1/ 2>/dev/null' | grep -qE '200|302' \
      && docker exec czfull-lab-grafana sh -c 'wget -qO- http://127.0.0.1:3000/api/health 2>/dev/null' | grep -q ok; then
      break
    fi
    sleep 2
  done
  docker ps --filter "name=^czfull-lab-" --format '{{.Names}}\t{{.Image}}\t{{.Status}}' | sort
}

change() {
  docker rm -f czfull-lab-redis >/dev/null                          # a host goes silent
  run nginx-new "$P.0.11" nginx:alpine                               # a new host appears
  docker rm -f czfull-lab-nginx >/dev/null                           # same address, newer nginx
  run nginx "$P.0.10" nginx:1.30.7-alpine
  docker exec czfull-lab-http-a sh -c "sed -i 's/<title>Czujka lab<\/title>/<title>Czujka lab v2<\/title>/' /srv/www/index.html"
  sleep 2
  docker ps --filter "name=^czfull-lab-" --format '{{.Names}}\t{{.Image}}\t{{.Status}}' | sort
}

case "${1:-}" in
  up) up ;;
  change) change ;;
  down) down ;;
  *) echo "usage: $0 up|change|down" >&2; exit 2 ;;
esac
