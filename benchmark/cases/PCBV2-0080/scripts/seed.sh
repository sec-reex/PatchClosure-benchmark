#!/usr/bin/env bash
# seed.sh — ArcadeDB: no post-start flag seeding needed.
# PCB_FLAG is used directly by verify.sh at probe time; no data is planted in
# the container by start.sh beyond the compose-up itself.
# Assumes containers are already up and healthy. Idempotent (no-op).
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}"
FLAG="${PCB_FLAG:-${RUN_FLAG:-}}"
if [[ -z "$FLAG" ]]; then
  echo "seed: PCB_FLAG or RUN_FLAG must be set" >&2
  exit 1
fi
echo "seed: ArcadeDB ${VERSION} — no explicit flag seeding needed"
