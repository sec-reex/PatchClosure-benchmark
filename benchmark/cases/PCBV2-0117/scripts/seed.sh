#!/usr/bin/env bash
# Pipeline wrapper: scoring/deploy run scripts/seed.sh on the compose HOST with
# PCB_FLAG/VERSION/COMPOSE_PROJECT_NAME set. The real idempotent seeding (site
# admin, private alice with the flag as email, public-only token) lives in
# scripts/verify.sh --seed. Keycloak/gitea can lag the container healthcheck,
# so retry the seed a few times before giving up.
set -u
export RUN_ID="${RUN_ID:-seed-$$}"
export WORK_DIR="${WORK_DIR:-/tmp/pcb-0117-seed-$$}"
export RUN_FLAG_REF="${RUN_FLAG_REF:-${RUN_FLAG:-${PCB_FLAG:?}}}"
export RUN_FLAG="${RUN_FLAG:-$RUN_FLAG_REF}"
rc=1
for i in 1 2 3 4 5; do
  bash "$(dirname "$0")/verify.sh" --seed && { rc=0; break; }
  rc=$?
  echo "seed: attempt $i failed rc=$rc; retrying" >&2
  sleep 10
done
exit $rc
