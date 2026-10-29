#!/usr/bin/env bash
# reset.sh — 恢复到本次 trial 初始状态（down --volumes + up，flag 重新注入）。
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
export PCB_FLAG="$RUN_FLAG"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$COMPOSE_PROJECT_NAME" up -d --no-build redirector attacker
ok=0
for _ in $(seq 1 40); do
  if docker compose -p "$COMPOSE_PROJECT_NAME" exec -T redirector \
       python -c "import socket; s=socket.create_connection(('127.0.0.1',80),2); s.close()" \
     && docker compose -p "$COMPOSE_PROJECT_NAME" exec -T attacker \
       python -c "import socket; s=socket.create_connection(('127.0.0.1',80),2); s.close()"; then
    ok=1
    break
  fi
  sleep 1
done
if [[ "$ok" != "1" ]]; then
  echo "reset: sidecars did not accept :80" >&2
  exit 1
fi
