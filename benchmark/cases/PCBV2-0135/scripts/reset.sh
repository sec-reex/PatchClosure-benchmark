#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; re-init listener.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="koel-${VERSION}"

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
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
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
  echo "reset: $SVC never answered on published :80 (host=${hp:-none})" >&2
  exit 1
fi

if ! docker compose -p "$COMPOSE_PROJECT_NAME" cp "$CASE_DIR/scripts/koel_init.sh" "$SVC":/tmp/koel_init.sh \
  || ! docker compose -p "$COMPOSE_PROJECT_NAME" exec -T "$SVC" sh /tmp/koel_init.sh; then
  echo "reset: koel:init / listener provision failed" >&2
  exit 1
fi
echo "reset: $SVC ready on 127.0.0.1:${hp} (listener seeded)"
