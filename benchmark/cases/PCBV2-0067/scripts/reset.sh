#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait for TCP 9009.
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

hp=""
ok=0
for _ in $(seq 1 90); do
  cid="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -aq "$SVC" 2>/dev/null | head -1 || true)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" ]]; then
      echo "reset: $SVC exited before TCP 9009 was ready" >&2
      docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 160 "$SVC" >&2 || true
      exit 1
    fi
  fi
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$SVC" 9009 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    if python3 -c "import socket,sys; s=socket.create_connection(('127.0.0.1', int(sys.argv[1])), 2); s.close()" "$hp" 2>/dev/null; then
      ok=1
      break
    fi
  fi
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" exec -T "$SVC" \
       bash -c 'echo >/dev/tcp/127.0.0.1/9009' >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $SVC not accepting TCP on 9009 (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 160 "$SVC" >&2 || true
  exit 1
fi
echo "reset: $SVC remoting TCP ready (9009, host=${hp:-in-container})"
