#!/usr/bin/env bash
# reset.sh — down --volumes + up --pull never with the same ports; wait; replant pcb_secret.
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

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

dc down --volumes --remove-orphans >/dev/null 2>&1 || true
ok_up=0
for i in 1 2 3; do
  if dc up -d --pull never; then
    ok_up=1
    break
  fi
  echo "reset: compose up retry $i" >&2
  dc down --volumes --remove-orphans >/dev/null 2>&1 || true
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "reset: compose up failed for profile $VERSION" >&2
  dc logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi

SVC="$VERSION"
PG="pg_${VERSION}"
ok=0
hp=""
for _ in $(seq 1 120); do
  hp="$(dc port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/login" || true)"
    if [[ "$code" == "200" ]]; then
      secret="$(dc exec -T "$PG" \
        psql -U postgres -tAc "SELECT secret FROM pcb_secret LIMIT 1" 2>/dev/null \
        | tr -d '\r' | head -1 | tr -d '[:space:]' || true)"
      if grep -Fq "$RUN_FLAG" <<<"$secret"; then
        ok=1
        break
      fi
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: pgAdmin $SVC did not become ready (host=$hp)" >&2
  dc logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
echo "reset: $SVC ready on 127.0.0.1:${hp}"
