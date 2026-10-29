#!/usr/bin/env bash
# reset.sh — 恢复到本次 trial 初始状态（down --volumes + up）。
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --pull missing
