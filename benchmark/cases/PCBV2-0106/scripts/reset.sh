#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same PORT_* / WP_HOST_PORT; wait ready.
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
SVC="wp-${VERSION}"
dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }
dc down --volumes --remove-orphans >/dev/null 2>&1 || true
dc up -d

wp_cid() { docker ps -aq --filter "name=${COMPOSE_PROJECT_NAME}-${SVC}" | head -1; }
ok=0
hp=""
for i in $(seq 1 180); do
  cid="$(wp_cid)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" || "$status" == "dead" ]]; then
      echo "reset: $SVC exited before ready" >&2
      dc logs --tail 80 "$SVC" >&2 || true
      exit 1
    fi
  fi
  hp="$(dc port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" && "$hp" != "<no value>" ]]; then
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/wp-login.php" || echo 000)"
    if [[ "$code" == "200" || "$code" == "302" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: WordPress $SVC not ready (wp-login; host=$hp)" >&2
  dc logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
echo "reset: $SVC ready on 127.0.0.1:${hp}"
