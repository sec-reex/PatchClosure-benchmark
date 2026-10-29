#!/usr/bin/env bash
# reset.sh — restart the node process (ReDoS wedges the event loop) with the same
# published ports; wait until GET /health and watchdog /status answer.
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
export VERSION
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d

_port_of() {
  local svc="$1" cport="$2"
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$svc" "$cport" 2>/dev/null \
    | sed 's/.*://' | tr -d '[:space:]' || true
}

ok=0
hp="" wd=""
for _ in $(seq 1 90); do
  hp="$(_port_of "$SVC" 3000)"
  wd="$(_port_of watchdog 8888)"
  if [[ -n "$hp" && -n "$wd" ]] \
     && curl -fsS --max-time 5 "http://127.0.0.1:${hp}/health" >/dev/null 2>&1 \
     && curl -fsS --max-time 5 "http://127.0.0.1:${wd}/status" >/dev/null 2>&1; then
    streak="$(curl -sS --max-time 5 "http://127.0.0.1:${wd}/status" 2>/dev/null \
      | python3 -c "import json,sys
try:
    print(int(json.load(sys.stdin).get('dbg',{}).get('ok_streak',0)))
except Exception:
    print(0)" 2>/dev/null || echo 0)"
    if [[ "${streak:-0}" -ge 3 ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $SVC did not become ready (host=${hp:-none} wd=${wd:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
echo "reset: $VERSION ready on 127.0.0.1:${hp} watchdog=${wd}"
