#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait until login works.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="$VERSION"
# shellcheck disable=SC1091
source "$CASE_DIR/.source.env"

if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
export PCB_FLAG="$RUN_FLAG"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

restore_img() {
  local official="$1" pin="$2"
  if docker image inspect "$official" >/dev/null 2>&1; then
    docker tag "$official" "$pin" >/dev/null 2>&1 || true
    return 0
  fi
  if docker image inspect "$pin" >/dev/null 2>&1; then
    docker tag "$pin" "$official"
    echo "reset: restored $official from $pin" >&2
    return 0
  fi
  echo "reset: missing $official" >&2
  return 1
}

ensure_images() {
  local ref=""
  case "$VERSION" in
    v0) ref="${V0:?}" ;;
    v1) ref="${V1:?}" ;;
    v2) ref="v0.8.4-rc1" ;;
    *) echo "reset: bad VERSION=$VERSION" >&2; return 1 ;;
  esac
  restore_img "${IMAGE:?}:${ref}" "pcb-0136-librechat:${ref}"
  restore_img "mongo:7.0" "pcb-0136-mongo:7.0"
}

ensure_images || exit 1
dc down --volumes --remove-orphans >/dev/null 2>&1 || true

ok_up=0
for i in 1 2 3; do
  ensure_images || true
  if dc up -d --pull never; then
    ok_up=1
    break
  fi
  echo "reset: compose up retry $i" >&2
  dc down --volumes --remove-orphans >/dev/null 2>&1 || true
  sleep 6
done
if [[ "$ok_up" != "1" ]]; then
  echo "reset: compose up failed for profile $VERSION" >&2
  exit 1
fi

hp=""
ok=0
for _ in $(seq 1 120); do
  hp="$(dc port "$SVC" 3080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/" || true)"
    if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then
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
