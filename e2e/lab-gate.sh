#!/usr/bin/env bash
# Merge gate for changes to the scan engine: one full /16 scan of the lab in
# state t0 through the product (e2e/lab-run.sh, the seeded default profile),
# scored against lab/ground-truth/t0.json, with the packets on the wire in
# one-second bins. Prints one table; exit 1 when a check fails.
#
#   e2e/lab-gate.sh                     build the image and run the gate
#   LR_SKIP_BUILD=1 CZUJKA_VERSION=acc6 e2e/lab-gate.sh
#
# Thresholds (environment, defaults from the best measured run, e2e/out/after:
# hosts 67/67, ports 123/155, technologies 100/104):
#   GATE_HOSTS=0.97 GATE_PORTS=0.75 GATE_TECH=0.90   recall at least
#   GATE_RAW_TOL=0.05   nmap's own packets: no second over cap x (1 + tol)
#   GATE_ALL_TOL=0.10 GATE_ALL_SECONDS=3   all packets (with the kernel's TCP of HTTP
#                       and version detection): at most this many seconds over cap x (1 + tol)
#   GATE_VERSIONS=0.90 GATE_TITLES=0.98   share right: service versions, page titles
#   GATE_STABLE=1   scan t0 a second time: the second run must report no
#                   tech_gone, tech_new, tech_version or service_changed change
#                   (the lab did not change; unstable hosts excused). GATE_STABLE=0 skips it.
# The run must end "completed" with no engine warning, and the Docker host's
# neighbour table must not overflow during the run (table_fulls unchanged).
set -uo pipefail
cd "$(dirname "$0")/.."
OUT=${GATE_OUT:-e2e/out/gate-$(date +%Y%m%d-%H%M%S)}
H=${GATE_HOSTS:-0.97}; P=${GATE_PORTS:-0.75}; T=${GATE_TECH:-0.90}
V=${GATE_VERSIONS:-0.90}; TT=${GATE_TITLES:-0.98}; STABLE=${GATE_STABLE:-1}
RT=${GATE_RAW_TOL:-0.05}; AT=${GATE_ALL_TOL:-0.10}; AS=${GATE_ALL_SECONDS:-3}
NB0=$(e2e/neigh-check.sh -json) || { echo "gate: the neighbour table is nearly full ($NB0); fix the host first"; exit 3; }
STATES=t0; [ "$STABLE" = 1 ] && STATES="t0 t0"
LR_NAME=gate LR_STATES="$STATES" LR_OUT="$OUT" e2e/lab-run.sh > "$OUT.log" 2>&1
RC=$?
[ -f "$OUT/score-t0.json" ] && [ -f "$OUT/pps-t0.json" ] && [ -f "$OUT/run-t0.json" ] || { echo "gate: the run did not finish (exit $RC), see $OUT.log"; tail -5 "$OUT.log"; exit 1; }
LAST=t0; [ "$STABLE" = 1 ] && LAST=t0-2
[ -f "$OUT/neigh-$LAST.json" ] && [ -f "$OUT/changes-$LAST.json" ] || { echo "gate: run $LAST did not finish, see $OUT.log"; exit 1; }
NB1=$(cat "$OUT/neigh-$LAST.json")
FAIL=0
row() { # name value limit ok
  printf '%-44s %-22s %-22s %s\n' "$1" "$2" "$3" "$([ "$4" = 1 ] && echo ok || echo FAIL)"
  [ "$4" = 1 ] || FAIL=1
}
rec() { jq -r --arg n "$1" '.metrics[] | select(.name == $n) | "\(.recall) \(.tp) \(.tp + .fn)"' "$OUT/score-t0.json"; }
ge() { awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 1e-9 >= b) }' && echo 1 || echo 0; }
CAP=$(jq .cap "$OUT/pps-t0.json")
printf '%-44s %-22s %-22s %s\n' check value limit result
for m in "hosts $H" "ports $P" "technologies $T"; do
  set -- $m; read -r R TP N <<< "$(rec "$1")"
  row "recall: $1" "$(printf '%.3f (%d/%d)' "$R" "$TP" "$N")" ">= $2" "$(ge "$R" "$2")"
done
acc() { jq -r --arg n "$1" '.accuracies[] | select(.name == $n) | "\(.share) \(.right) \(.total)"' "$OUT/score-t0.json"; }
for m in "service versions|$V" "page titles|$TT"; do
  IFS='|' read -r NM LIM <<< "$m"; read -r R TP N <<< "$(acc "$NM")"
  row "share right: $NM" "$(printf '%.3f (%d/%d)' "$R" "$TP" "$N")" ">= $LIM" "$(ge "$R" "$LIM")"
done
if [ "$STABLE" = 1 ]; then
  UNST=$(jq -c '[.unstable[]?.ip]' "$OUT/score-t0.json")
  FLAPS=$(jq -r --argjson u "$UNST" '[.items[]? | select(.kind == "tech_gone" or .kind == "tech_new" or .kind == "tech_version" or .kind == "service_changed") | select(.ip as $i | $u | index($i) | not)]' "$OUT/changes-t0-2.json")
  NF=$(echo "$FLAPS" | jq length); NALL=$(jq '.items | length' "$OUT/changes-t0-2.json")
  row "stability: t0 twice, changes in run 2" "$NF of $NALL changes" "0 tech/version" "$([ "$NF" = 0 ] && echo 1 || echo 0)"
  echo "$FLAPS" | jq -r '.[] | "  \(.kind) \(.ip):\(.port) \(.summary)"' | head -20
fi
ST=$(jq -r .status "$OUT/run-t0.json"); W=$(jq -r '.stats.warnings // [] | length' "$OUT/run-t0.json")
row "run status" "$ST" "completed" "$([ "$ST" = completed ] && echo 1 || echo 0)"
row "engine warnings" "$W" "0" "$([ "$W" = 0 ] && echo 1 || echo 0)"
RAWMAX=$(jq .raw_max_per_s "$OUT/pps-t0.json"); RAWLIM=$(awk -v c="$CAP" -v t="$RT" 'BEGIN { printf "%d", c * (1 + t) }')
row "nmap packets: max per second" "$RAWMAX" "<= $RAWLIM (cap $CAP)" "$([ "$RAWMAX" -le "$RAWLIM" ] && echo 1 || echo 0)"
ALLLIM=$(awk -v c="$CAP" -v t="$AT" 'BEGIN { printf "%d", c * (1 + t) }')
ALLOVER=$(go run ./e2e/ppsbins -src "${LR_IP:-10.66.0.30}" -cap "$ALLLIM" -json <(gunzip -c "$OUT/tcpdump-t0.txt.gz") | jq .all_seconds_over_cap)
ALLMAX=$(jq .all_max_per_s "$OUT/pps-t0.json"); ALLP99=$(jq .all_p99_per_s "$OUT/pps-t0.json"); SECS=$(jq .seconds "$OUT/pps-t0.json")
row "all packets: seconds over $ALLLIM" "$ALLOVER of $SECS (max $ALLMAX)" "<= $AS" "$([ "$ALLOVER" -le "$AS" ] && echo 1 || echo 0)"
row "all packets: p99 per second" "$ALLP99" "<= $CAP" "$([ "$ALLP99" -le "$CAP" ] && echo 1 || echo 0)"
for K in t0 t0-2; do
  [ -f "$OUT/passtimes-$K.txt" ] || continue
  read -r PG PD PH PW PN < "$OUT/passtimes-$K.txt"
  printf '%-44s %-22s %-22s %s\n' "wall time $K: general pass / deep pass" "$PG s / $PD s" "deep: $PH hosts" "info ($PW waiting, $PN new)"
done
# the kernel cap must be active and drop nothing in a normal run (both runs)
if [ -s "$OUT/kcap-t0.json" ] && [ "$(cat "$OUT/kcap-t0.json")" != null ]; then
  KC=""; KOK=1
  for K in t0 t0-2; do
    [ -f "$OUT/kcap-$K.json" ] || continue
    A=$(jq -r '.active' "$OUT/kcap-$K.json"); D=$(jq -r '.dropped // 0' "$OUT/kcap-$K.json")
    KC="$KC$K $A/$D "
    { [ "$A" = true ] && [ "$D" = 0 ]; } || KOK=0
  done
  row "kernel cap: active/dropped per run" "$KC" "true/0" "$KOK"
fi
F0=$(echo "$NB0" | jq .table_fulls); F1=$(echo "$NB1" | jq .table_fulls)
row "neighbour table: entries after, overflows" "$(echo "$NB1" | jq .entries) / +$((F1 - F0))" "+0 overflows" "$([ "$F1" = "$F0" ] && echo 1 || echo 0)"
printf 'run %s s, %s hosts up, %s open services, %s packets; output %s\n' "$(jq .stats.elapsed_sec "$OUT/run-t0.json")" "$(jq .stats.hosts_up "$OUT/run-t0.json")" \
  "$(jq .stats.services_open "$OUT/run-t0.json")" "$(jq .stats.packets_sent "$OUT/run-t0.json")" "$OUT"
[ "$FAIL" = 0 ] && echo "GATE PASSED" || echo "GATE FAILED"
exit $FAIL
