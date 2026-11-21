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
APPNET=czeng-apps
IMG=czeng-lab:latest

down() {
  docker ps -aq --filter "name=^czeng-" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$NET" "$SCANNET" "$WIDENET" "$APPNET" >/dev/null 2>&1 || true
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

# apps starts real applications in their own network, 10.76.0.0/24, for the
# fingerprint scenario. The lab is throwaway: passwords are random and exist
# only inside these containers.
apps() {
  docker ps -aq --filter "name=^czeng-app-" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$APPNET" >/dev/null 2>&1 || true
  docker build -q -t "$IMG" lab >/dev/null
  docker network create --subnet 10.76.0.0/24 --gateway 10.76.0.1 "$APPNET" >/dev/null
  local pw; pw=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
  app() { local name=$1 ip=$2; shift 2
    docker run -d --name "czeng-app-$name" --hostname "$name" --network "$APPNET" --ip "$ip" "$@" >/dev/null; }
  app db         10.76.0.10 -e MARIADB_ROOT_PASSWORD="$pw" -e MARIADB_DATABASE=wp -e MARIADB_USER=wp -e MARIADB_PASSWORD="$pw" mariadb:11
  app wordpress  10.76.0.11 -e WORDPRESS_DB_HOST=10.76.0.10 -e WORDPRESS_DB_USER=wp -e WORDPRESS_DB_PASSWORD="$pw" -e WORDPRESS_DB_NAME=wp wordpress:6-apache
  app grafana    10.76.0.20 grafana/grafana:11.3.0
  app gitea      10.76.0.21 -e GITEA__security__INSTALL_LOCK=true gitea/gitea:1.22
  app phpmyadmin 10.76.0.30 -e PMA_HOST=10.76.0.10 phpmyadmin:5
  app tomcat     10.76.0.40 tomcat:10.1-jdk17
  app https      10.76.0.50 -e ROLE=https -e PORT=8443 "$IMG"
  app udp        10.76.0.70 -e ROLE=udp "$IMG"
  app nginx-odd  10.76.0.60 nginx:alpine sh -c "sed -i 's/listen  *80;/listen 8181;/' /etc/nginx/conf.d/default.conf && exec nginx -g 'daemon off;'"
  echo "waiting for the applications..."
  wait_http() { # container url
    for _ in $(seq 1 90); do docker exec "$1" sh -c "curl -s -o /dev/null -m 3 '$2' || wget -q -T 3 -O /dev/null '$2'" 2>/dev/null && return 0; sleep 2; done
    echo "$1 did not answer on $2" >&2; return 1; }
  # install WordPress, so the site shows its real front page (lab set-up, not
  # part of any scan); repeat until the database is ready and the page answers 200
  local code=000
  for _ in $(seq 1 60); do
    docker exec czeng-app-wordpress curl -s -o /dev/null -m 60 -H 'Host: 10.76.0.11' 'http://localhost/wp-admin/install.php?step=2' \
      --data-urlencode 'weblog_title=Czujka lab' --data-urlencode 'user_name=labadmin' --data-urlencode "admin_password=$pw" \
      --data-urlencode "admin_password2=$pw" --data-urlencode 'pw_weak=1' --data-urlencode 'admin_email=lab@example.com' --data-urlencode 'blog_public=0' || true
    code=$(docker exec czeng-app-wordpress curl -s -o /dev/null -m 20 -w '%{http_code}' -H 'Host: 10.76.0.11' http://localhost/ || true)
    [ "$code" = 200 ] && break
    sleep 2
  done
  [ "$code" = 200 ] || { echo "WordPress was not installed (front page answers $code)" >&2; return 1; }
  wait_http czeng-app-grafana http://localhost:3000/login
  wait_http czeng-app-gitea http://localhost:3000/
  wait_http czeng-app-tomcat http://localhost:8080/ || true
  docker ps --filter "name=^czeng-app-" --format '{{.Names}}\t{{.Status}}' | sort
}

case "${1:-}" in
  up) up ;;
  apps) apps ;;
  down) down ;;
  *) echo "usage: $0 up|apps|down" >&2; exit 2 ;;
esac
