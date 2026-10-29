#!/usr/bin/env bash
# seed.sh — Git submodule injection: no post-start flag seeding needed.
# PCB_FLAG is used directly by the oracle/verify probe at runtime.
# The probe is exec-style (docker run ... sh /victim.sh) rather than a
# long-running service, so there is no persistent state to seed.
# Assumes containers/images are already built. Idempotent (no-op).
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}"
FLAG="${PCB_FLAG:-${RUN_FLAG:-}}"
if [[ -z "$FLAG" ]]; then
  echo "seed: PCB_FLAG or RUN_FLAG must be set" >&2
  exit 1
fi
echo "seed: Git ${VERSION} — no explicit flag seeding needed"
