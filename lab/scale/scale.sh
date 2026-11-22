#!/usr/bin/env bash
# The scale lab: thousands of live addresses served by a few "farm"
# containers (real TCP/IP stacks, real nginx, Dropbear and lighttpd), behind
# a routed hop, so the scanner sees one routed /16 (10.77.0.0/16).
#
#   lab/scale/scale.sh build                 farm image czscale-farm:1
#   lab/scale/scale.sh up N [COUNT]          network czscale-net and farms 1..N (COUNT addresses each, default 1000)
#   lab/scale/scale.sh routes CONTAINER N    routes of 10.77.0.0/16 in CONTAINER's network namespace
#   lab/scale/scale.sh truth N [COUNT]       ground truth (JSON on stdout), same rules as farm/entrypoint.sh
#   lab/scale/scale.sh stop-farm K | start-farm K
#   lab/scale/scale.sh down                  farms and network
#
# Why routed: the kernel neighbour (ARP) table is one table for the whole
# docker host (gc_thresh3 is often 1024). Thousands of addresses on one
# bridge would fill it and break every container on the machine. Here each
# farm owns its addresses on a dummy interface; the scanner routes
# 10.77.4(K-1).0/22 to farm K, so the scanner needs one neighbour entry per
# farm. Addresses of 10.77.0.0/16 that no farm owns are routed to farm 1,
# which drops them (no forwarding): dead addresses, no packet leaves.
# Farm K stands at 10.78.0.(10+K) on czscale-net (10.78.0.0/24, internal:
# no route out); the scanner at 10.78.0.2. The docker host's bridge address
# 10.78.0.1 is outside the scanned /16.
set -euo pipefail
cd "$(dirname "$0")"
NET=czscale-net
IMG=czscale-farm:1

farm_ip() { echo "10.78.0.$((10 + $1))"; }

case "${1:-}" in
build)
  docker build -q -t "$IMG" farm >/dev/null && docker image ls "$IMG" --format '{{.Repository}}:{{.Tag}} {{.Size}}' ;;
up)
  N=${2:?farms}; COUNT=${3:-1000}
  docker network inspect "$NET" >/dev/null 2>&1 || docker network create --internal --subnet 10.78.0.0/24 "$NET" >/dev/null
  for k in $(seq 1 "$N"); do
    docker rm -f "czscale-farm$k" >/dev/null 2>&1 || true
    docker run -d --name "czscale-farm$k" --hostname "farm$k" --network "$NET" --ip "$(farm_ip "$k")" \
      --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=0 --ulimit nofile=8192:8192 --memory 384m --pids-limit 512 -e FARM="$k" -e COUNT="$COUNT" --restart no "$IMG" >/dev/null
  done
  sleep 3
  for k in $(seq 1 "$N"); do docker logs "czscale-farm$k" 2>&1 | tail -1; done ;;
routes)
  C=${2:?container}; N=${3:?farms}
  CMD="ip route replace 10.77.0.0/16 via $(farm_ip 1)"
  for k in $(seq 1 "$N"); do CMD="$CMD && ip route replace 10.77.$((4 * (k - 1))).0/22 via $(farm_ip "$k")"; done
  docker run --rm --network "container:$C" --cap-add NET_ADMIN alpine:3.22 sh -c "$CMD && ip -4 route | grep 10.77" ;;
truth)
  N=${2:?farms}; COUNT=${3:-1000}
  V=$(docker run --rm --entrypoint sh "$IMG" -c 'nginx -v 2>&1; dropbear -V 2>&1 | head -1; lighttpd -v 2>&1 | head -1')
  python3 - "$N" "$COUNT" "$V" <<'PY'
import json, re, sys
n, count, v = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
ngx = re.search(r"nginx/([0-9.]+)", v).group(1)
drop = re.search(r"Dropbear v([0-9.]+)", v).group(1)
light = re.search(r"lighttpd/([0-9.]+)", v).group(1)
tcp, closed = count * 9 // 10, count // 20
def web(port, product, version, title, status=200, location=None, tls=False):
    s = {"port": port, "proto": "tcp", "name": "https" if tls else "http", "product": product, "version": version,
         "technologies": [{"name": product, "category": "web-server", "version": version}],
         "tech_optional": ["HSTS", "TLS"], "class_optional": ["default-page", "redirect", "self-signed-cert", "tls"],
         "http": {"status": status, "title": title, "server": f"{product}/{version}"}}
    if tls:
        s["tunnel"] = "ssl"; s["name_alt"] = ["http", "ssl/http"]
    if location:
        s["http"]["location"] = location
    return s
hosts = []
for k in range(1, n + 1):
    b3 = 4 * (k - 1)
    for i in range(count):
        ip = f"10.77.{b3 + i // 250}.{i % 250 + 1}"
        h = {"ip": ip, "name": f"farm{k}-{i:04d}", "hostnames": [], "group": f"farm{k}", "services": []}
        if i < tcp:
            m = i % 10
            ssh = {"port": 22, "proto": "tcp", "name": "ssh", "product": "Dropbear sshd", "version": drop,
                   "technologies": [{"name": "Dropbear SSH", "category": "other", "version": drop, "aliases": ["dropbear", "dropbear sshd"]}],
                   # Czujka's class rules put Dropbear (common on embedded devices) in "iot"; the lab does not say either way
                   "class_optional": ["remote-access", "iot"]}
            h["services"].append(ssh)
            if m == 5:
                h["services"].append(web(80, "nginx", ngx, f"Farm start {ip}", 301, f"http://{ip}/start/"))
                h["desc"] = "nginx 80 (301 -> /start/), Dropbear 22"
            else:
                h["services"].append(web(80, "nginx", ngx, f"Farm host {ip}"))
                h["desc"] = "nginx 80, Dropbear 22"
            if m in (0, 1, 2):
                h["services"].append(web(443, "nginx", ngx, f"Farm host {ip}", tls=True)); h["desc"] += ", nginx TLS 443"
            if m in (3, 4):
                h["services"].append(web(8080, "lighttpd", light, "Farm lighttpd")); h["desc"] += ", lighttpd 8080"
            h["services"].sort(key=lambda s: s["port"])
        elif i < tcp + closed:
            h["desc"] = "live, every TCP port closed"
        else:
            h["desc"] = "live, ICMP only"
        hosts.append(h)
print(json.dumps({"state": f"scale-{n}x{count}", "network": "10.77.0.0/16",
    "note": f"Generated by lab/scale/scale.sh truth: {n * count} live addresses served by {n} farm containers. nginx {ngx}, Dropbear {drop}, lighttpd {light}.",
    "ignore": [], "hosts": hosts}, indent=1))
PY
  ;;
stop-farm) docker stop -t 2 "czscale-farm${2:?farm}" >/dev/null && echo "farm $2 stopped" ;;
start-farm) docker start "czscale-farm${2:?farm}" >/dev/null && sleep 3 && docker logs "czscale-farm$2" 2>&1 | tail -1 ;;
down)
  docker ps -aq --filter name=czscale-farm | xargs -r docker rm -f >/dev/null
  docker network rm "$NET" >/dev/null 2>&1 || true
  echo "farms and $NET removed" ;;
*) sed -n 2,26p "$0"; exit 2 ;;
esac
