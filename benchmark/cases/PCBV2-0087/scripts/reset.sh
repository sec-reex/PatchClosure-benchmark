#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait for Rails.
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
dc up -d

case "$VERSION" in
  v0) SVCS="app_v0_local" ;;
  v1) SVCS="app_v1_local app_v1_s3" ;;
  v2) SVCS="app_v2_s3" ;;
  *) echo "reset: unknown VERSION=$VERSION" >&2; exit 1 ;;
esac

wait_http() {
  local svc="$1"
  local hp="" code=""
  for _ in $(seq 1 180); do
    cid="$(dc ps -aq "$svc" 2>/dev/null | head -1 || true)"
    if [[ -n "$cid" ]]; then
      status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
      if [[ "$status" == "exited" ]]; then
        echo "reset: $svc exited before Rails was ready" >&2
        dc logs --tail 160 "$svc" >&2 || true
        return 1
      fi
    fi
    hp="$(dc port "$svc" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
    if [[ -n "$hp" ]]; then
      code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 "http://127.0.0.1:${hp}/admin/login" || echo 000)"
      if [[ "$code" =~ ^[12345][0-9][0-9]$ ]]; then
        echo "reset: $svc ready on 127.0.0.1:${hp} (http ${code})"
        return 0
      fi
    fi
    sleep 2
  done
  echo "reset: $svc not ready on published :3000 (host=${hp:-none})" >&2
  dc ps >&2 || true
  dc logs --tail 160 "$svc" >&2 || true
  return 1
}

for svc in $SVCS; do
  wait_http "$svc" || exit 1
done
