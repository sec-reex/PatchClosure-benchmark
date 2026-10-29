#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait until ready.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="$VERSION"
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
export PCB_FLAG="$RUN_FLAG"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d

ok=0
hp=""
for _ in $(seq 1 150); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$SVC" 6806 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  vic="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port victim 8070 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  cb="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port callback 9000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" && -n "$vic" && -n "$cb" ]]; then
    a="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
      "http://127.0.0.1:${hp}/api/icon/getDynamicIcon?type=8&content=ok" || true)"
    v="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${vic}/health" || true)"
    c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${cb}/health" || true)"
    if [[ "$a" == "200" && "$v" == "200" && "$c" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $SVC did not become ready (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
echo "reset: $VERSION ready on 127.0.0.1:${hp}"
