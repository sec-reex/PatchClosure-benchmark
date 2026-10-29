#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait until admin login.
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
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d

ok=0
hp=""
for _ in $(seq 1 300); do
  cid="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -aq "$VERSION" 2>/dev/null | head -1 || true)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" ]]; then
      echo "reset: Pimcore $VERSION exited before admin was ready" >&2
      docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 160 "$VERSION" >&2 || true
      exit 1
    fi
    hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
    if [[ -n "$hp" ]]; then
      login="$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${hp}/admin/login" || true)"
      cidf="$(curl -sS -m 5 "http://127.0.0.1:${hp}/pcb_class_id.txt" || true)"
      if [[ "$login" == "200" || "$login" == "302" ]] && printf '%s' "$cidf" | grep -qE '^[0-9]+$'; then
        ok=1
        break
      fi
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: Pimcore $VERSION admin not ready on published :80 (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 160 "$VERSION" >&2 || true
  exit 1
fi
echo "reset: $VERSION Pimcore admin ready on 127.0.0.1:${hp}"
