#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same ports; wait; replant flag.
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

SVC="$VERSION"
ok=0
hp=""
for _ in $(seq 1 120); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/login" || true)"
    if [[ "$code" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: pgAdmin $SVC did not answer /login (host=$hp)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
docker compose -p "$COMPOSE_PROJECT_NAME" exec -T "$SVC" \
  sh -c "printf '%s\n' \"$RUN_FLAG\" > /tmp/pcb_flag" || {
  echo "reset: could not plant /tmp/pcb_flag in $SVC" >&2
  exit 1
}
echo "reset: $SVC ready on 127.0.0.1:${hp}"
