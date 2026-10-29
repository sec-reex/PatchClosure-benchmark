#!/usr/bin/env bash
# reset.sh — recreate this trial's stack with the same published ports; wait until ready.
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

_port_of() {
  local svc="$1" cport="$2"
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$svc" "$cport" 2>/dev/null \
    | sed 's/.*://' | tr -d '[:space:]' || true
}

_grid_ready() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" exec -T browser \
    curl -fsS --max-time 5 http://127.0.0.1:4444/wd/hub/status >/dev/null 2>&1 \
    || docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" exec -T browser \
      curl -fsS --max-time 5 http://127.0.0.1:4444/status >/dev/null 2>&1
}

ok=0
app_hp=""
for _ in $(seq 1 120); do
  app_hp="$(_port_of "$SVC" 80)"
  vic_hp="$(_port_of victim 8070)"
  cb_hp="$(_port_of callback 9000)"
  if [[ -n "$app_hp" && -n "$vic_hp" && -n "$cb_hp" ]] \
     && curl -fsS --max-time 5 "http://127.0.0.1:${app_hp}/health" >/dev/null 2>&1 \
     && curl -fsS --max-time 5 "http://127.0.0.1:${vic_hp}/health" >/dev/null 2>&1 \
     && curl -fsS --max-time 5 "http://127.0.0.1:${cb_hp}/health" >/dev/null 2>&1 \
     && _grid_ready; then
    ok=1
    break
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $SVC did not become ready (host=${app_hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
echo "reset: $VERSION ready on 127.0.0.1:${app_hp}"
