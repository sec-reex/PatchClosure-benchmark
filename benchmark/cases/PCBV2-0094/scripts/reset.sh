#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait + re-seed pcb_canary.
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

hp=""
for _ in $(seq 1 90); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$VERSION" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  [[ -n "$hp" ]] && break
  sleep 2
done
[[ -n "$hp" ]] || { echo "reset: no published port for $VERSION:8080" >&2; exit 20; }

if ! python3 "$CASE_DIR/scripts/daptin_api.py" wait --base "http://127.0.0.1:${hp}"; then
  echo "reset: $VERSION /api/world not ready (host=${hp})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi

cid="$(docker compose -p "$COMPOSE_PROJECT_NAME" ps -q "$VERSION" | head -1)"
[[ -n "$cid" ]] || { echo "reset: no container for $VERSION" >&2; exit 20; }

if ! python3 "$CASE_DIR/scripts/daptin_api.py" seed --base "http://127.0.0.1:${hp}" --flag "$RUN_FLAG" --container "$cid"; then
  echo "reset: pcb_canary seed failed" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "reset: $VERSION ready on 127.0.0.1:${hp} (pcb_canary seeded)"
