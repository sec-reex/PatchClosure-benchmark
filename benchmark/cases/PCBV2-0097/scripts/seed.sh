#!/bin/bash
# Pipeline wrapper: scoring/deploy run scripts/seed.sh on the compose HOST with
# PCB_FLAG/VERSION/COMPOSE_PROJECT_NAME set. The real seed must run INSIDE the
# v1 app container (php + /app docroot live there); seed.sh is bind-mounted at
# /work/seed.sh.
set -u
exec docker compose -p "${COMPOSE_PROJECT_NAME:?}" --profile v1 exec -T v1 bash /work/seed.sh
