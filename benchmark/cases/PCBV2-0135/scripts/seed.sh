#!/usr/bin/env bash
# Pipeline wrapper: scoring/deploy run scripts/seed.sh on the compose HOST with
# PCB_FLAG/VERSION/COMPOSE_PROJECT_NAME set. The real init (koel:init + sqlite
# creation + non-admin listener + canary) lives in scripts/start.sh and must run
# on the host (docker compose cp/exec). PORT_* are derived from the running
# project containers so the scored instance is never recreated elsewhere.
set -u
export RUN_ID="${RUN_ID:-seed-$$}"
export RUN_FLAG="${RUN_FLAG:-${PCB_FLAG:?}}"
export VERSION="${VERSION:-v1}"
export WORK_DIR="${WORK_DIR:-/tmp/pcb-0135-seed-$$}"

port_of() {
  docker ps --filter "name=${COMPOSE_PROJECT_NAME}-${1}" --format '{{.Ports}}' 2>/dev/null \
    | grep -oE '0\.0\.0\.0:[0-9]+' | head -1 | cut -d: -f2
}
p0="$(port_of koel-v0)"; p1="$(port_of koel-v1)"; p2="$(port_of koel-v2)"
[ -n "${p1:-}" ] || { echo "seed: koel-v1 container not running for ${COMPOSE_PROJECT_NAME}" >&2; exit 20; }
export PORT_V0_0="${PORT_V0_0:-${p0:-0}}" PORT_V1_0="${PORT_V1_0:-$p1}" PORT_V2_0="${PORT_V2_0:-${p2:-0}}"

exec bash "$(dirname "$0")/start.sh"
