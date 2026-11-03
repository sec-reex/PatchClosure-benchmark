#!/usr/bin/env bash
# Pipeline wrapper: scoring/deploy run scripts/seed.sh on the compose HOST with
# PCB_FLAG/VERSION/COMPOSE_PROJECT_NAME set. Per the compose header, the per-run
# canary is planted into the running manager container at /flag (single clean
# line — a trailing newline breaks the OOB URI). Idempotent per replant.
set -u
export RUN_ID="${RUN_ID:-seed-$$}"
export WORK_DIR="${WORK_DIR:-/tmp/pcb-0159-seed-$$}"
RUN_FLAG="${RUN_FLAG:-${PCB_FLAG:?}}"
docker compose -p "${COMPOSE_PROJECT_NAME:?}" exec -T manager \
  sh -c 'printf "%s" "$1" > /flag' sh "${RUN_FLAG}"
rc=$?
echo "seed: flag planted rc=$rc"
exit $rc
