#!/usr/bin/env bash
# reset.sh — keep the official stack; do not down -v (re-embed is expensive).
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
# shellcheck disable=SC1091
source "$CASE_DIR/.source.env"
case "$VERSION" in
  v0) export OWUI_IMAGE="${IMAGE}:${V0}" ;;
  v1) export OWUI_IMAGE="${IMAGE}:${V1}" ;;
  v2) export OWUI_IMAGE="${IMAGE}:${V2:-0.9.6}" ;;
  *) echo "reset: bad VERSION=$VERSION" >&2; exit 30 ;;
esac
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
export PCB_FLAG="$RUN_FLAG" OWUI_IMAGE
docker compose -p "$COMPOSE_PROJECT_NAME" up -d
hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port openwebui 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
ok=0
for _ in $(seq 1 60); do
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/health" || true)"
    if [[ "$code" == "200" ]]; then ok=1; break; fi
  fi
  sleep 5
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port openwebui 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
done
if [[ "$ok" != "1" ]]; then
  echo "reset: Open WebUI not healthy (host=$hp)" >&2
  exit 1
fi
echo "reset: ${OWUI_IMAGE} still ready on 127.0.0.1:${hp}"
