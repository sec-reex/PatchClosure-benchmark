#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait until
# GET /health and watchdog baseline (fresh PCB_FLAG after a hung/OOM worker).
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
hp=""
wd=""
for _ in $(seq 1 90); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$VERSION" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  wd="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port watchdog 8888 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" && -n "$wd" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${hp}/health" || true)"
    wst="$(curl -sS -m 3 "http://127.0.0.1:${wd}/status" 2>/dev/null || true)"
    streak="$(printf '%s' "$wst" | python3 -c "import json,sys
try:
    print(int(json.load(sys.stdin).get('dbg',{}).get('ok_streak',0)))
except Exception:
    print(0)" 2>/dev/null || echo 0)"
    if [[ "$code" == "200" && "$streak" -ge 3 ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $VERSION not ready (host=${hp:-none} wd=${wd:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "reset: $VERSION ready on 127.0.0.1:${hp} watchdog=${wd}"
