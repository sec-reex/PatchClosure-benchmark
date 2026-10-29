#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; re-setup root.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="newapi-${VERSION}"
PY="${PCB_PYTHON:-python3}"

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
ok=0
for _ in $(seq 1 120); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$SVC" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    body="$(curl -sS --max-time 5 "http://127.0.0.1:${hp}/api/status" || true)"
    if printf '%s' "$body" | grep -q '"success"'; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $SVC never answered /api/status on published :3000 (host=${hp:-none})" >&2
  exit 1
fi

if ! "$PY" "$CASE_DIR/poc/driver.py" setup "http://127.0.0.1:${hp}"; then
  echo "reset: new-api setup failed on 127.0.0.1:${hp}" >&2
  exit 1
fi
echo "reset: $SVC ready on 127.0.0.1:${hp}"
