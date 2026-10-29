#!/usr/bin/env bash
# reset.sh — keep the official stack; clear collector hits and replant /flag.
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

COLL="$(docker compose -p "$COMPOSE_PROJECT_NAME" port collector 8000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -n "$COLL" ]]; then
  curl -sS --max-time 10 "http://127.0.0.1:${COLL}/reset" >/dev/null || true
fi

docker compose -p "$COMPOSE_PROJECT_NAME" exec -T -u 0 manager \
  sh -c "printf '%s' \"$RUN_FLAG\" > /flag" || {
  echo "reset: could not replant /flag" >&2
  exit 1
}
echo "reset: collector cleared, /flag replanted"
