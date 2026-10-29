#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait for WordPress.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="wp-${VERSION}"
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

wp_cid() { docker ps -aq --filter "name=${COMPOSE_PROJECT_NAME}-${SVC}" | head -1; }
hp=""
ok=0
code=""
for _ in $(seq 1 150); do
  cid="$(wp_cid)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" ]]; then
      echo "reset: $SVC exited before WordPress was ready" >&2
      docker ps -a --filter "name=${COMPOSE_PROJECT_NAME}" --format 'table {{.Names}}\t{{.Status}}' >&2 || true
      dc logs --tail 160 "$SVC" >&2 || true
      exit 1
    fi
  fi
  hp="$(dc port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -z "$hp" && -n "$cid" ]]; then
    hp="$(docker inspect -f '{{(index (index .NetworkSettings.Ports "80/tcp") 0).HostPort}}' "$cid" 2>/dev/null | tr -d '[:space:]' || true)"
  fi
  if [[ -n "$hp" && "$hp" != "<no value>" ]]; then
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/wp-login.php" || echo 000)"
    if [[ "$code" =~ ^[12345][0-9][0-9]$ ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $SVC not ready on published :80 /wp-login.php (host=${hp:-none})" >&2
  docker ps -a --filter "name=${COMPOSE_PROJECT_NAME}" --format 'table {{.Names}}\t{{.Status}}' >&2 || true
  dc logs --tail 160 "$SVC" >&2 || true
  exit 1
fi
echo "reset: $SVC ready on 127.0.0.1:${hp} (http ${code})"
