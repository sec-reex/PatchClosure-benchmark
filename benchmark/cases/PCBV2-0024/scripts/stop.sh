#!/usr/bin/env bash
# stop.sh — stop and delete this run's containers/network/volumes/temp source (COMPOSE_PROJECT_NAME only).
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile v0 --profile v1 --profile v2 down --volumes --remove-orphans >/dev/null 2>&1 || true
rm -rf "$WORK_DIR"
