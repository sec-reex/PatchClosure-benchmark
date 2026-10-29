#!/usr/bin/env bash
# start.sh — compose up the versioned log4j driver + internal LDAP canary.
# No host ports. Wait until the version container's canary is listening on :1389.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
export PCB_FLAG="$RUN_FLAG"

img="pcb/log4j-jndi:2.14.1"
[[ "$VERSION" == "v1" ]] && img="pcb/log4j-jndi:2.15.0"
[[ "$VERSION" == "v2" ]] && img="pcb/log4j-jndi:2.16.0"
if docker image inspect "$img" >/dev/null 2>&1; then
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d
else
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build
fi

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
  echo "start: $VERSION LDAP canary not ready on 127.0.0.1:1389" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 >&2 || true
  exit 1
fi
