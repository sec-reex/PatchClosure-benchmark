#!/usr/bin/env bash
# stop.sh — stop this run's compose project only (no profiles; no other cases).
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
docker compose -p "$COMPOSE_PROJECT_NAME" down --volumes --remove-orphans >/dev/null 2>&1 || true
rm -rf "$WORK_DIR"
