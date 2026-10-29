#!/usr/bin/env bash
# reset.sh — 恢复到本次 trial 初始状态（down --volumes + up，flag 重新注入）。
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
export PCB_FLAG="$RUN_FLAG"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$COMPOSE_PROJECT_NAME" up -d victim redirector attacker
ok=""
for _ in $(seq 1 30); do
  n="$(docker compose -p "$COMPOSE_PROJECT_NAME" ps -q victim redirector attacker 2>/dev/null | wc -l | tr -d '[:space:]')"
  if [[ "$n" == "3" ]]; then ok=1; break; fi
  sleep 1
done
[[ -n "$ok" ]] || { echo "reset: sidecars not running" >&2; exit 1; }
