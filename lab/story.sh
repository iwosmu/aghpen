#!/bin/sh
# Scripted story of real changes in the lab, for a demo of the history:
# hosts appear and disappear, versions change, a certificate is replaced, an
# admin panel and a database port show up, a staging page comes and goes,
# office devices go dark for the "night" and come back. The flapper and the
# time-of-day hosts keep their own rhythm all the time (lab/README.md).
#
# Every step is a real docker or labsim action; nothing is written into the
# product. Each step is logged with its UTC time to a JSON-lines file, so a
# scan at any moment can be compared with what the lab really was then:
#   truth = lab/ground-truth/<state>.json without the hosts in "stopped".
#
# Usage:
#   lab/story.sh                     2 cycles, 15 minutes per step (17 steps, about 4 h 15 min)
#   STORY_STEP=5 STORY_CYCLES=1 lab/story.sh
#   STORY_LOG=e2e/out/story.jsonl lab/story.sh
# Run Czujka against the lab every few minutes meanwhile (a profile with a
# schedule interval) and, for a demo, the lab clock (docs/ALGORYTMY.md 2.10).
# At the end the lab is back in state t0 with every container running.
set -eu
cd "$(dirname "$0")"
STEP_MIN=${STORY_STEP:-15}
CYCLES=${STORY_CYCLES:-2}
LOG=${STORY_LOG:-../e2e/out/story-$(date -u +%Y%m%d-%H%M%S).jsonl}
mkdir -p "$(dirname "$LOG")"
COMPOSE="docker compose -f docker-compose.yml"

STATE=t0
STOPPED=""   # compose services stopped by the story (host names, space separated)

log_step() { # step-name note
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  stopped_json=$(printf '%s\n' $STOPPED | awk 'NF {printf "%s\"%s\"", (n++ ? "," : ""), $0}')
  printf '{"at":"%s","step":"%s","state":"%s","stopped":[%s],"note":"%s"}\n' "$ts" "$1" "$STATE" "$stopped_json" "$2" >> "$LOG"
  echo "[$ts] $1: $2 (state $STATE, stopped: ${STOPPED:-none})"
}
stop() { $COMPOSE stop "$@" >/dev/null 2>&1; for s in "$@"; do STOPPED="$STOPPED $s"; done; }
start() {
  $COMPOSE start "$@" >/dev/null 2>&1
  for s in "$@"; do STOPPED=$(printf '%s\n' $STOPPED | grep -vx "$s" | tr '\n' ' '); done
}
# scenario.sh starts every container of the state; the story keeps its own stops
state() {
  ./scenario.sh "$1" >/dev/null
  STATE=$1
  # shellcheck disable=SC2086
  [ -z "$(echo $STOPPED)" ] || $COMPOSE stop $STOPPED >/dev/null 2>&1
}
hold() { sleep $((STEP_MIN * 60)); }

trap 'echo "story interrupted: restoring t0"; $COMPOSE start memcached printer-1 cam-1 nas-1 staging-portal >/dev/null 2>&1 || true; ./scenario.sh t0 >/dev/null || true' INT TERM

state t0
stop memcached
log_step start "baseline t0; the memcached database port is closed"
hold
c=1
while [ "$c" -le "$CYCLES" ]; do
  stop printer-1 cam-1 nas-1
  log_step night "printer, camera and NAS switched off for the night"
  hold
  start printer-1 cam-1 nas-1
  log_step morning "printer, camera and NAS back"
  hold
  state t1
  log_step t1 "new hosts 10.66.130.77 and 10.66.5.5; WordPress, nginx, PHP and InfoKiosk upgraded; news page becomes an admin panel; certificate of 10.66.50.10 replaced; FTP and legacy PHP hosts gone; port 8000 -> 8081"
  hold
  start memcached
  log_step db-open "memcached database port 11211 opens"
  hold
  stop staging-portal
  log_step staging-off "staging portal disappears"
  hold
  start staging-portal
  log_step staging-on "staging portal is back"
  hold
  state t2
  log_step t2 "certificate of 10.66.50.12 replaced; redirect changed; legacy PHP host back; 10.66.5.5 gone; port 31337 closed; API status and access_token cookie changed"
  hold
  state t0
  stop memcached
  log_step back-to-t0 "every change undone; memcached closed again (cycle $c of $CYCLES)"
  hold
  c=$((c + 1))
done
start memcached
log_step end "story finished; lab in t0, all containers running"
echo "log: $LOG"
