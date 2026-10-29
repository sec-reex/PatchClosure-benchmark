#!/usr/bin/env bash
# seed.sh — Plant per-run flag at /flag inside already-running OpenRemote manager container.
# No trailing newline — it breaks the KNX OOB URI.
# Assumes containers are already up and healthy. Idempotent (overwrites file).
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FLAG="${PCB_FLAG:-${RUN_FLAG:-}}"
if [[ -z "$FLAG" ]]; then
  echo "seed: PCB_FLAG or RUN_FLAG must be set" >&2
  exit 1
fi

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" "$@"; }

# Plant per-run canary. No trailing newline — it breaks the KNX OOB URI.
if ! dc exec -T -u 0 manager \
  sh -c "printf '%s' \"$FLAG\" > /flag"; then
  echo "seed: could not plant /flag in manager" >&2
  exit 1
fi
echo "seed: OpenRemote /flag planted in manager container"
