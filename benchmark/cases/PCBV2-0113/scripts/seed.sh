#!/usr/bin/env bash
# seed.sh — FreeScout: no post-start flag seeding needed from host.
# Container entrypoint runs artisan migrate + create-user + seed automatically.
# The flag rides in the callback URL query constructed by verify.sh at probe time.
# Assumes containers are already up and healthy. Idempotent (no-op).
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}"
FLAG="${PCB_FLAG:-${RUN_FLAG:-}}"
if [[ -z "$FLAG" ]]; then
  echo "seed: PCB_FLAG or RUN_FLAG must be set" >&2
  exit 1
fi
echo "seed: FreeScout ${VERSION} — seeding handled by container entrypoint"
