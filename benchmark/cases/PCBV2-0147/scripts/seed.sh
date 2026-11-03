#!/usr/bin/env bash
# Pipeline wrapper: scoring/deploy run scripts/seed.sh on the compose HOST with
# PCB_FLAG/VERSION/COMPOSE_PROJECT_NAME set. The real idempotent seeding (the
# flag-carrying SECRET_BOOK document) lives in scripts/verify.sh --seed; it
# derives the planted value from RUN_FLAG_REF and hard-requires RUN_ID/WORK_DIR.
set -u
export RUN_ID="${RUN_ID:-seed-$$}"
export WORK_DIR="${WORK_DIR:-/tmp/pcb-0147-seed-$$}"
export RUN_FLAG_REF="${RUN_FLAG_REF:-${RUN_FLAG:-${PCB_FLAG:?}}}"
export RUN_FLAG="${RUN_FLAG:-$RUN_FLAG_REF}"
exec bash "$(dirname "$0")/verify.sh" --seed
