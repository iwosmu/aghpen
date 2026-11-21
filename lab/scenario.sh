#!/bin/sh
# Moves the lab to a named state: t0, t1 or t2. The result does not depend on
# the state before. Usage: lab/scenario.sh t1
#
# What a state means is defined in lab/manifest (see lab/README.md). This
# script only (1) stops the containers that the state does not have,
# (2) starts the ones it has and waits until they are healthy, and
# (3) writes the state name to the shared volume that every labsim host reads.
set -eu
cd "$(dirname "$0")"
. ./generated/states.sh

state="${1:-}"
case " $LAB_STATES " in
  *" $state "*) ;;
  *) echo "usage: $0 <$(echo "$LAB_STATES" | tr ' ' '|')>" >&2; exit 2 ;;
esac

COMPOSE="docker compose -f docker-compose.yml"
eval "stop=\$STOP_$state"
eval "up=\$UP_$state"

if [ -n "$stop" ]; then
  # shellcheck disable=SC2086
  $COMPOSE stop $stop >/dev/null 2>&1 || true
fi
# shellcheck disable=SC2086
$COMPOSE up -d --no-recreate --wait --wait-timeout "${LAB_WAIT_TIMEOUT:-900}" $up

$COMPOSE exec -T scanner-box sh -c "echo $state > /lab-state/current"
# labsim polls the state file every second.
sleep 3
applied=$($COMPOSE exec -T kiosk-1 cat /tmp/labsim.state 2>/dev/null || true)
if [ "$applied" != "$state" ]; then
  echo "labsim did not apply state $state (kiosk-1 says: $applied)" >&2
  exit 1
fi
echo "lab is in state $state"
