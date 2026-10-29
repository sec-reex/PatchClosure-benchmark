#!/usr/bin/env bash
# reset.sh — seed is a read; keep the same published ports and wait until ssx serves.
# Do not wipe volumes: XWiki first-boot is minutes and reset timeout is 600s.
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
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d

hp=""
ok=0
for _ in $(seq 1 120); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$VERSION" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 \
      "http://127.0.0.1:${hp}/bin/ssx/Main/WebHome?resource=pcb-ready-check&minify=false" 2>/dev/null || true)"
    if [[ "$code" =~ ^(200|404)$ ]]; then
      ok=1
      break
    fi
  fi
  sleep 5
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $VERSION ssx never ready on published 8080 (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "reset: $VERSION ready on 127.0.0.1:${hp}"
