#!/usr/bin/env bash
# Trade-off of scan profiles on the lab in state t0: every variant is one
# e2e/lab-run.sh run (fresh product, REST API only) of the seeded default
# profile with some fields replaced. Prints a Markdown table.
#
#   e2e/lab-tradeoff.sh                  all variants below
#   TO_ONLY="top100 top1000" e2e/lab-tradeoff.sh
set -uo pipefail
cd "$(dirname "$0")/.."
OUT=${TO_OUT:-e2e/out/tradeoff-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
export CZUJKA_VERSION=${CZUJKA_VERSION:-acc2}
# name|profile override (merged into the seeded default profile)
VARIANTS='
default|{}
top100|{"ports":"top-100","udp":{"enabled":false}}
top1000|{"ports":"top-1000","udp":{"enabled":false}}
vi2|{"version_intensity":2}
noudp|{"udp":{"enabled":false}}
cap800|{"rate":{"max_pps":800,"max_parallel_chunks":4}}
pps300|{"rate":{"max_pps":300,"max_parallel_chunks":2}}
'
if [ "${TO_BUILD:-1}" = 1 ]; then
  docker compose -p czacc -f deploy/docker-compose.yml build czujka >"$OUT/build.log" 2>&1 || { tail -20 "$OUT/build.log"; exit 1; }
fi
row() { # name dir
  local d=$2 s=$2/score-t0.json r=$2/run-t0.json
  [ -f "$s" ] || { echo "| $1 | failed |"; return; }
  local wall tx
  wall=$(sed -n 's/.*wall=\([0-9]*\).*/\1/p' "$d/runs.txt"); tx=$(sed -n 's/.*tx=\([0-9]*\).*/\1/p' "$d/runs.txt")
  printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n" "$1" "$wall" "$tx" \
    "$(jq '.stats.avg_pps | floor' "$r")" "$(jq '"\(.raw_max_per_s) / \(.cap)"' -r "$d/pps-t0.json")" "$(jq .raw_p99_per_s "$d/pps-t0.json")" "$(jq .stats.http_requests "$r")" \
    "$(jq -r '.metrics[0] | "\(.tp)/\(.tp + .fn)"' "$s")" "$(jq -r '.metrics[1] | "\(.tp)/\(.tp + .fn)"' "$s")" \
    "$(jq -r '.metrics[0].f1 * 1000 | floor / 1000' "$s")" "$(jq -r '.metrics[1].f1 * 1000 | floor / 1000' "$s")" \
    "$(jq -r '.metrics[1].f1 * 1000 | floor / 1000' "$d/score-strict-t0.json")"
}
echo "| wariant | czas [s] | pakiety | śr. pps | maks. pps (1 s, nmap) | p99 pps | żądania HTTP | hosty | porty | F1 hostów | F1 portów | F1 portów (strict) |" > "$OUT/table.md"
echo "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |" >> "$OUT/table.md"
echo "$VARIANTS" | while IFS='|' read -r name over; do
  [ -n "$name" ] || continue
  case " ${TO_ONLY:-$name} " in *" $name "*) ;; *) continue ;; esac
  echo "[$(date +%H:%M:%S)] variant $name: $over"
  LR_NAME=$name LR_STATES=t0 LR_SKIP_BUILD=1 LR_FINAL_STATE= LR_OUT="$OUT/$name" LR_PROFILE="$over" e2e/lab-run.sh > "$OUT/$name.log" 2>&1
  row "$name" "$OUT/$name" | tee -a "$OUT/table.md"
done
echo; cat "$OUT/table.md"
