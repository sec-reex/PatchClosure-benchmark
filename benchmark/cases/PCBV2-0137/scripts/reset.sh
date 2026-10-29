#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait until login works.
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

hp=""
ok=0
for _ in $(seq 1 120); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$SVC" 3080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    acode="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
      -H 'Content-Type: application/json' \
      -d '{"email":"ready@pcb.local","password":"PcbPass123!"}' \
      "http://127.0.0.1:${hp}/api/auth/login" || true)"
    if [[ "$acode" =~ ^[1-5][0-9][0-9]$ ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $SVC never answered on published :3080 (host=${hp:-none})" >&2
  exit 1
fi

for i in 1 2 3 4 5; do
  curl -sS --max-time 15 -H 'Content-Type: application/json' \
    -d '{"name":"pcbready","email":"ready@pcb.local","password":"PcbPass123!","confirm_password":"PcbPass123!"}' \
    "http://127.0.0.1:${hp}/api/auth/register" >/dev/null 2>&1 || true
  tok="$(curl -sS --max-time 15 -H 'Content-Type: application/json' \
    -d '{"email":"ready@pcb.local","password":"PcbPass123!"}' \
    "http://127.0.0.1:${hp}/api/auth/login" || true)"
  if grep -q '"token"' <<<"$tok"; then
    echo "reset: $SVC ready on 127.0.0.1:${hp}"
    exit 0
  fi
  sleep 4
done
echo "reset: registration never ready on 127.0.0.1:${hp}" >&2
exit 1
