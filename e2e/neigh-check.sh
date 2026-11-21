#!/usr/bin/env bash
# Prints the kernel neighbour (ARP) table of the Docker host: entries, limits,
# table_fulls and the number of "neighbor table overflow" lines in the kernel log.
# The table and its limits are global for all network namespaces: when it is
# full, lab containers stop answering ARP (a Linux host sends an ARP reply only
# when it can store the asker) and every scan on the machine loses hosts and ports.
#
#   e2e/neigh-check.sh          one line, exit 1 when the table is over 80 % of gc_thresh3
#   e2e/neigh-check.sh -json    the same as JSON
# On Docker Desktop the "host" is the Linux VM; on Linux it is the machine itself.
set -uo pipefail
MODE=${1:-}
RAW=$(docker run --rm --privileged --pid=host --net=host alpine:3.22 nsenter -t 1 -m -u -n -i sh -c \
  'cat /proc/sys/net/ipv4/neigh/default/gc_thresh3; tail -n +2 /proc/net/stat/arp_cache; echo "overflow $(dmesg 2>/dev/null | grep -c "table overflow")"' 2>/dev/null)
[ -n "$RAW" ] || { echo "neigh-check: cannot read the Docker host's neighbour table" >&2; exit 2; }
THRESH=$(echo "$RAW" | sed -n 1p)
ENTRIES=$((16#$(echo "$RAW" | sed -n 2p | awk '{print $1}')))
FULLS=0
while read -r line; do
  set -- $line
  [ "$#" -ge 13 ] && FULLS=$((FULLS + 16#${13}))
done < <(echo "$RAW" | sed -n '2,$p' | grep -v overflow)
OVER=$(echo "$RAW" | awk '/^overflow/ {print $2}')
if [ "$MODE" = -json ]; then
  printf '{"entries":%d,"gc_thresh3":%d,"table_fulls":%d,"overflow_lines":%d}\n' "$ENTRIES" "$THRESH" "$FULLS" "$OVER"
else
  echo "neighbour table: $ENTRIES entries, gc_thresh3 $THRESH, table_fulls $FULLS, overflow lines $OVER"
fi
[ "$ENTRIES" -le $((THRESH * 8 / 10)) ]
