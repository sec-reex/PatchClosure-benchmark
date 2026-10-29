#!/usr/bin/env bash
# reset.sh — restore this trial's initial state (down --volumes + up, flag re-injected).
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
export PCB_FLAG="$RUN_FLAG"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d

ok=0
for _ in $(seq 1 60); do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" exec -T "$VERSION" \
       python3 -c "import socket; s=socket.create_connection(('127.0.0.1',1389),2); s.close()" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $VERSION LDAP canary not ready" >&2
  exit 1
fi
