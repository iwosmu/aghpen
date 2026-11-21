#!/bin/sh
# Baseline scan of the lab with plain nmap, run from the scanner box.
# It checks the lab itself, and it gives the numbers Czujka must beat.
#
#   e2e/labscan.sh <tag> [outdir]     for example: e2e/labscan.sh t0 /tmp/czujka-scan
#
# Steps: (1) ping sweep of the whole /16, (2) TCP scan of all ports with
# service detection and four safe scripts on the live hosts, (3) UDP scan of
# three ports, (4) conversion to a Czujka JSON export. Only GET and HEAD
# requests are sent; no login, no brute force, no intrusive script.
# (-sV also runs nmap's own "version" scripts, for example mqtt-subscribe; all are in the "safe" category.)
#
# LABSCAN_TCP_PORTS limits the TCP ports (default "-": all 65535), for a quick re-check:
#   LABSCAN_TCP_PORTS=$(jq -r '[.hosts[].services[]|select(.proto=="tcp").port]|unique|join(",")' lab/ground-truth/t2.json) e2e/labscan.sh t2
set -eu
tag="${1:?usage: labscan.sh <tag> [outdir]}"
out="${2:-e2e/out}"
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
box="docker compose -f $root/lab/docker-compose.yml exec -T scanner-box"

t0=$(date +%s)
$box nmap -sn -n -T4 --min-rate 3000 --max-retries 2 10.66.0.0/16 -oX - > "$out/sweep-$tag.xml"
t1=$(date +%s)
# Live hosts, without the gateway and the scanner box itself.
tr '\n' ' ' < "$out/sweep-$tag.xml" | sed 's/<host>/\n<host>/g' | grep 'state="up"' \
  | sed -n 's/.*<address addr="\([0-9.]*\)" addrtype="ipv4".*/\1/p' \
  | grep -v -x -e 10.66.0.1 -e 10.66.0.10 > "$out/live-$tag.txt"
echo "sweep: $(wc -l < "$out/live-$tag.txt" | tr -d ' ') live hosts in $((t1 - t0)) s"

$box nmap -sU -sV -p 53,123,161 -n -T4 -iL - -oX - < "$out/live-$tag.txt" > "$out/udp-$tag.xml" &
$box nmap -sS -sV -p "${LABSCAN_TCP_PORTS:--}" -n -T4 --min-rate 1000 \
  --script http-title,http-server-header,http-headers,ssl-cert --script-args http-headers.useget \
  -iL - -oX - < "$out/live-$tag.txt" > "$out/tcp-$tag.xml"
wait
t2=$(date +%s)
echo "service scan: $((t2 - t1)) s"

(cd "$root" && go run ./e2e/nmap2czujka -o "$out/export-$tag.json" "$out/sweep-$tag.xml" "$out/tcp-$tag.xml" "$out/udp-$tag.xml")
echo "export: $out/export-$tag.json"
echo "done-$tag" > "$out/done-$tag"
