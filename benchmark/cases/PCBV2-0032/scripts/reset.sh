#!/usr/bin/env bash
# reset.sh — down --volumes + up; wait until perl -MDBI -e1 and planted flag exist.
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
for _ in $(seq 1 60); do
  CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -q "$VERSION" 2>/dev/null | head -1 | tr -d '[:space:]')"
  if [[ -n "$CID" ]] \
     && docker exec "$CID" perl -MDBI -e1 >/dev/null 2>&1 \
     && docker exec "$CID" test -s /pcb_flag.txt >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $VERSION not ready (perl -MDBI /pcb_flag.txt)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "reset: $VERSION ready (perl -MDBI -e1)"
