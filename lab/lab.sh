#!/bin/sh
# Start, stop and inspect the Czujka test lab.
#   lab/lab.sh build     build the custom images
#   lab/lab.sh up        cold start into state t0, wait until every host is healthy
#   lab/lab.sh down      stop and remove containers, network and volumes (images stay)
#   lab/lab.sh status    container health summary
#   lab/lab.sh stats     memory and CPU per container, with totals
#   lab/lab.sh sh ...    run a command in the scanner box (default: a shell)
set -eu
cd "$(dirname "$0")"
COMPOSE="docker compose -f docker-compose.yml"

case "${1:-}" in
  build)
    $COMPOSE --profile later build
    ;;
  up)
    t0=$(date +%s)
    $COMPOSE --profile later build -q
    ./scenario.sh t0
    echo "start took $(( $(date +%s) - t0 )) s"
    ;;
  down)
    $COMPOSE --profile later down -v --remove-orphans
    ;;
  status)
    $COMPOSE --profile later ps -a --format '{{.Service}}\t{{.State}}\t{{.Health}}' | sort | awk -F'\t' '
      { n++; s[$2 "/" $3]++; if ($2 == "running" && $3 != "healthy") bad = bad "  " $1 " (" $3 ")\n" }
      END { for (k in s) printf "%4d  %s\n", s[k], k; if (bad != "") printf "not healthy:\n%s", bad }'
    ;;
  stats)
    docker stats --no-stream --format '{{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}' $($COMPOSE --profile later ps -q) | sort | awk -F'\t' '
      function mib(v) { if (v ~ /GiB/) { sub(/GiB.*/, "", v); return v * 1024 } if (v ~ /MiB/) { sub(/MiB.*/, "", v); return v + 0 } if (v ~ /KiB/) { sub(/KiB.*/, "", v); return v / 1024 } return 0 }
      { split($2, m, " / "); mem += mib(m[1]); cpu += $3 + 0; n++; printf "%-34s %12s %8s\n", $1, m[1], $3 }
      END { printf "TOTAL: %d containers, %.0f MiB memory, %.1f%% CPU\n", n, mem, cpu }'
    ;;
  sh)
    shift
    if [ $# -eq 0 ]; then exec $COMPOSE exec scanner-box sh; fi
    exec $COMPOSE exec -T scanner-box "$@"
    ;;
  *)
    sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
