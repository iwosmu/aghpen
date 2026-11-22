#!/bin/sh
# Farm FARM (1..) of the scale lab. It owns COUNT addresses (at most 1000):
# address i (0-based) is 10.77.(4*(FARM-1) + i/250).(i%250 + 1).
#   i in [0, TCP)               live, nginx 80 and Dropbear 22; by i%10:
#                               0,1,2 also TLS 443; 3,4 also lighttpd 8080; 5: port 80 redirects
#   i in [TCP, TCP+CLOSED)      live, every TCP port closed (RST)
#   i in [TCP+CLOSED, COUNT)    live, answers ICMP only (TCP and UDP dropped)
# lab/scale/scale.sh truth computes the ground truth with the same rules.
set -eu
FARM=${FARM:?}
COUNT=${COUNT:-1000}
TCP=$((COUNT * 9 / 10))
CLOSED=$((COUNT / 20))
B3=$((4 * (FARM - 1)))
addr() { echo "10.77.$((B3 + $1 / 250)).$(($1 % 250 + 1))"; }

ip link add scale0 type dummy 2>/dev/null || true
ip link set scale0 up
i=0; : > /tmp/ip.batch
while [ $i -lt $COUNT ]; do echo "addr add $(addr $i)/32 dev scale0" >> /tmp/ip.batch; i=$((i + 1)); done
ip -batch /tmp/ip.batch

# closed and ICMP-only slices (contiguous address ranges)
C0=$(addr $TCP); C1=$(addr $((TCP + CLOSED - 1)))
I0=$(addr $((TCP + CLOSED))); I1=$(addr $((COUNT - 1)))
cat > /tmp/fw.nft <<EOF
table inet farm {
  # dead addresses of 10.77.0.0/16 (routed here, owned by nobody) stay silent
  chain pre {
    type filter hook prerouting priority -150; policy accept;
    ip daddr 10.77.0.0/16 fib daddr type != local drop
  }
  chain input {
    type filter hook input priority 0; policy accept;
    ip daddr $C0-$C1 meta l4proto tcp reject with tcp reset
    ip daddr $I0-$I1 meta l4proto { tcp, udp } drop
  }
}
EOF
nft -f /tmp/fw.nft

# TLS certificate (self-signed, one per farm)
mkdir -p /etc/farm
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=farm$FARM.scale.czujka.test" \
  -keyout /etc/farm/key.pem -out /etc/farm/cert.pem 2>/dev/null

TLSL=; REDL=; LIGHT=
i=0
while [ $i -lt $TCP ]; do
  a=$(addr $i)
  case $((i % 10)) in
    0|1|2) TLSL="$TLSL    listen $a:443 ssl;
" ;;
    3|4) [ $i -eq 3 ] || LIGHT="$LIGHT\$SERVER[\"socket\"] == \"$a:8080\" { }
" ;;
    5) REDL="$REDL    listen $a:80;
" ;;
  esac
  i=$((i + 1))
done
PAGE='default_type text/html; return 200 "<!doctype html><html><head><title>Farm host $server_addr</title></head><body><h1>farm</h1></body></html>";'
cat > /etc/nginx/nginx.conf <<EOF
worker_processes 2;
worker_rlimit_nofile 8192;
error_log /dev/stderr warn;
pid /tmp/nginx.pid;
events { worker_connections 4096; }
http {
  server_tokens on;
  access_log off;
  server {
    listen 80 default_server;
    location / { $PAGE }
  }
  server {
$REDL    location = /start/ { default_type text/html; return 200 "<!doctype html><html><head><title>Farm start \$server_addr</title></head><body>start</body></html>"; }
    location / { return 301 /start/; }
  }
  server {
$TLSL    ssl_certificate /etc/farm/cert.pem;
    ssl_certificate_key /etc/farm/key.pem;
    location / { $PAGE }
  }
}
EOF
mkdir -p /srv/light
echo '<!doctype html><html><head><title>Farm lighttpd</title></head><body>lighttpd</body></html>' > /srv/light/index.html
FIRST=$(addr 3)
cat > /etc/lighttpd/farm.conf <<EOF
server.document-root = "/srv/light"
server.bind = "$FIRST"
server.port = 8080
server.pid-file = "/tmp/lighttpd.pid"
server.errorlog = "/dev/stderr"
index-file.names = ( "index.html" )
mimetype.assign = ( ".html" => "text/html" )
$LIGHT
EOF
nginx -t -q
mkdir -p /etc/dropbear
lighttpd -f /etc/lighttpd/farm.conf
# -s: no password logins at all; -R: host keys made on the first connection
dropbear -R -s -p 22
echo "farm $FARM: $COUNT addresses ($(addr 0) .. $(addr $((COUNT - 1)))), $TCP with services, $CLOSED closed, $((COUNT - TCP - CLOSED)) ICMP only"
exec nginx -g 'daemon off;'
