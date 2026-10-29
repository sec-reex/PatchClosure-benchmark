#!/usr/bin/env bash
# reset.sh — down + up same ports; wait loginAuth (wrapper re-plants flags).
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
dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }
dc down --volumes --remove-orphans >/dev/null 2>&1 || true
dc up -d

hp=""
ok=0
for _ in $(seq 1 120); do
  cid="$(dc ps -aq "$SVC" 2>/dev/null | head -1 || true)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" || "$status" == "dead" ]]; then
      echo "reset: $SVC $status before HTTP ready" >&2
      dc logs --tail 160 "$SVC" >&2 || true
      exit 1
    fi
  fi
  hp="$(dc port "$SVC" 6806 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
      -H 'Content-Type: application/json' \
      -d '{"authCode":"pcb"}' \
      "http://127.0.0.1:${hp}/api/system/loginAuth" || true)"
    if [[ "$code" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $SVC never answered POST /api/system/loginAuth (host=${hp:-none})" >&2
  dc ps >&2 || true
  dc logs --tail 160 "$SVC" >&2 || true
  exit 1
fi
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  printf 'PUBLISHED_PORT=%s\n' "$hp" >> "$WORK_DIR/compose.env"
fi
echo "reset: $SVC ready on 127.0.0.1:${hp}"
