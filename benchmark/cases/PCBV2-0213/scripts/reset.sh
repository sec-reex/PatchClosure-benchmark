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
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d

SVC="wp-${VERSION}"
ok=0
hp=""
for i in $(seq 1 180); do
  cid="$(docker compose -p "$COMPOSE_PROJECT_NAME" ps -aq "$SVC" 2>/dev/null | head -1)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" ]]; then
      echo "reset: $SVC exited before ready" >&2
      docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
      exit 1
    fi
    if [[ "$status" == "running" ]] \
       && docker compose -p "$COMPOSE_PROJECT_NAME" exec -T "$SVC" \
            test -f /flag/ready 2>/dev/null; then
      hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
      if [[ -n "$hp" ]]; then
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/wp-login.php" || true)"
        if [[ "$code" == "200" ]]; then
          ok=1
          break
        fi
      fi
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: WordPress $SVC not ready (wp-login + /flag/ready; host=$hp)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
echo "reset: $SVC ready on 127.0.0.1:${hp}"
