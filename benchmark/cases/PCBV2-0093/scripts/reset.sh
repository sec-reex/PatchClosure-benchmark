#!/usr/bin/env bash
# reset.sh — 恢复到本次 trial 初始状态（down --volumes + up，flag 重新注入）。
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
export PCB_FLAG="$RUN_FLAG"
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/ports.env" ]]; then
  # shellcheck disable=SC2046
  export $(grep -E '^PORT_' "$WORK_DIR/ports.env" | xargs) || true
fi
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d
