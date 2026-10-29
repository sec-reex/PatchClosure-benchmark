#!/usr/bin/env bash
# stop.sh — stop this run's containers/volumes/workdir only. Do not rmi b3log/siyuan:*.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile v0 --profile v1 --profile v2 down --volumes --remove-orphans >/dev/null 2>&1 || true
rm -rf "$WORK_DIR"
