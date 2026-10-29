#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait PROVIDER_READY.
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
export PCB_FLAG="${PLANTED_FLAG:-$RUN_FLAG}"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --no-build

_cid() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -aq "$SVC" 2>/dev/null | head -1
}

hp=""
ok=0
for _ in $(seq 1 90); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$SVC" 20880 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  cid="$(_cid)"
  if [[ -n "$hp" && -n "$cid" ]] && docker logs --tail 80 "$cid" 2>/dev/null | grep -q 'PROVIDER_READY'; then
    ok=1
    break
  fi
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" || "$status" == "dead" ]]; then
      docker start "$cid" >/dev/null 2>&1 || true
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $SVC never printed PROVIDER_READY (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
sleep 5
echo "reset: $SVC ready on 127.0.0.1:${hp}"
