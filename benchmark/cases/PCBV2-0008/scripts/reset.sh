#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait until GET /health
# and watchdog baseline (fresh PCB_FLAG after a wedged event loop).
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

ok=0
hp=""
for _ in $(seq 1 60); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$SVC" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
      "http://127.0.0.1:${hp}/health" || true)"
    if [[ "$code" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $SVC did not become ready (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi

wd=""
wd_ok=0
for _ in $(seq 1 30); do
  wd="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port watchdog 8888 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$wd" ]]; then
    st="$(curl -sS -m 5 "http://127.0.0.1:${wd}/status" 2>/dev/null || true)"
    if printf '%s' "$st" | grep -q '"ok_streak": 3'; then
      wd_ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$wd_ok" != "1" ]]; then
  echo "reset: watchdog baseline not ready (host=${wd:-none})" >&2
  exit 1
fi
echo "reset: $VERSION ready on 127.0.0.1:${hp}; watchdog :${wd}"
