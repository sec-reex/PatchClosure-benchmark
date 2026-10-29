#!/usr/bin/env bash
# reset.sh — 恢复到本次 trial 初始状态（down --volumes + up，flag 重新注入）。
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
export PCB_FLAG="$RUN_FLAG"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --pull never
HP="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$VERSION" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$HP" ]]; then
  case "$VERSION" in
    v0) HP="${PORT_V0_0:-}" ;;
    v1) HP="${PORT_V1_0:-}" ;;
    *) HP="${PORT_V2_0:-}" ;;
  esac
fi
[[ -n "$HP" ]] || { echo "reset: no published port for $VERSION:3000" >&2; exit 20; }
python3 "$CASE_DIR/scripts/init_gogs.py" "$HP"
