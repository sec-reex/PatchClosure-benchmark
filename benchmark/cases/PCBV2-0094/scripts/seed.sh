#!/usr/bin/env bash
# Pipeline wrapper: scoring/deploy run scripts/seed.sh on the compose HOST with
# PCB_FLAG/VERSION/COMPOSE_PROJECT_NAME set. The real seeding lives in
# scripts/start.sh (registers admin, creates the pcb_canary entity, inserts the
# flag); it must run on the host (needs python3 + docker compose API access).
set -u
export RUN_ID="${RUN_ID:-seed-$$}"
export RUN_FLAG="${RUN_FLAG:-${PCB_FLAG:?}}"
export VERSION="${VERSION:-v1}"
export WORK_DIR="${WORK_DIR:-/tmp/pcb-0094-seed-$$}"

# start.sh recreates the stack with RANDOM ports if PORT_* are unset, which
# would move the instance off the scored port. Derive the live published ports
# from the running project containers instead.
port_of() { # <service-suffix> <container-port>
  docker ps --filter "name=${COMPOSE_PROJECT_NAME}-${1}" --format '{{.Ports}}' 2>/dev/null \
    | grep -oE '0\.0\.0\.0:[0-9]+' | head -1 | cut -d: -f2
}
p0="$(port_of v0 8080)"; p1="$(port_of v1 8080)"; p2="$(port_of v2 8080)"
[ -n "${p1:-}" ] || { echo "seed: v1 container not running for ${COMPOSE_PROJECT_NAME}" >&2; exit 20; }
export PORT_V0_0="${PORT_V0_0:-${p0:-0}}" PORT_V1_0="${PORT_V1_0:-$p1}" PORT_V2_0="${PORT_V2_0:-${p2:-0}}"

exec bash "$(dirname "$0")/start.sh"
