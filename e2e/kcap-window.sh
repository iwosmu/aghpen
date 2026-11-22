#!/usr/bin/env bash
# Wire check of the kernel packet cap (internal/kcap) on one lab-run capture.
# Counts the packets the cap counts (TCP SYN, UDP except DNS to the lab
# resolver, ICMP echo and timestamp requests) sent by the scanner, in fixed
# 100 ms and 1 s bins. Prints one line:
#   max100 <n> at <time> max1s <n> at <time> near <bins>
# "near" lists the 100 ms bins at 90 % of the burst or more, each with the
# bin before it (prev/this): a clipped catch-up after a stall shows there.
# Usage: e2e/kcap-window.sh tcpdump.txt[.gz] scanner-ip burst
set -euo pipefail
F=$1 IP=$2 BURST=$3
cat_f() { case "$F" in *.gz) gunzip -c "$F" ;; *) cat "$F" ;; esac; }
cat_f | awk -v ip="$IP" -v burst="$BURST" '
  $3 ~ "^"ip"\\." && ($0 ~ /Flags \[S\],/ || $0 ~ /ICMP echo request/ || $0 ~ /ICMP time stamp query/ || (($0 ~ / UDP/ || $0 ~ /udp/) && $5 !~ /^10\.66\.0\.53\.53:/)) {
    b = int($1 * 10); n[b]++; s[int($1)]++
  }
  function hms(t,   c) { c = "date -r " int(t) " +%H:%M:%S"; c | getline r; close(c); return r }
  END {
    m = 0; for (k in n) if (n[k] > m) { m = n[k]; mk = k }
    m1 = 0; for (k in s) if (s[k] > m1) { m1 = s[k]; m1k = k }
    near = ""
    for (k in n) if (n[k] >= 0.9 * burst) near = near sprintf("%s.%d:%d/%d ", hms(k / 10), k % 10, n[k - 1] + 0, n[k])
    printf "max100 %d at %s.%d max1s %d at %s near %s\n", m, hms(mk / 10), mk % 10, m1, hms(m1k), (near == "" ? "-" : near)
  }'
