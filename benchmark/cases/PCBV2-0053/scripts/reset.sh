#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait health.
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

_grid_ready() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" exec -T callback \
    python3 -c "import urllib.request; urllib.request.urlopen('http://browser:4444/status', timeout=5).read()" \
    >/dev/null 2>&1 \
  || docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" exec -T callback \
    python3 -c "import urllib.request; urllib.request.urlopen('http://browser:4444/wd/hub/status', timeout=5).read()" \
    >/dev/null 2>&1
}

app=""; cb=""; vic=""
ok=0
for _ in $(seq 1 180); do
  app="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  cb="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port callback 9000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  vic="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port victim 8070 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$app" && -n "$cb" && -n "$vic" ]]; then
    if curl -fsS --max-time 5 "http://127.0.0.1:${app}/health" >/dev/null 2>&1 \
       && curl -fsS --max-time 5 "http://127.0.0.1:${cb}/health" >/dev/null 2>&1 \
       && curl -fsS --max-time 5 "http://127.0.0.1:${vic}/health" >/dev/null 2>&1 \
       && _grid_ready; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: antisamy stack not ready (app=${app:-none} cb=${cb:-none} vic=${vic:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  exit 1
fi
echo "reset: $SVC ready on 127.0.0.1:${app}"
