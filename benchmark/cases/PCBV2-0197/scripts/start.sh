#!/usr/bin/env bash
# start.sh — compose up the versioned spring-web driver + internal sidecar.
# No host ports. Wait until sidecar :8080 and the version container are usable.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
export PCB_FLAG="$RUN_FLAG"
# Build only if the pinned image is missing; --build would redo apt/mvn every trial.
img="pcb/spring-web:6.1.4"
[[ "$VERSION" == "v1" ]] && img="pcb/spring-web:6.1.5"
[[ "$VERSION" == "v2" ]] && img="pcb/spring-web:6.1.6"
if docker image inspect "$img" >/dev/null 2>&1; then
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d
else
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build
fi

ok=0
for _ in $(seq 1 60); do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" exec -T sidecar \
       python3 -c "import socket; s=socket.create_connection(('127.0.0.1',8080),2); s.close()" >/dev/null 2>&1 \
     && docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" exec -T "$VERSION" \
       python3 -c "import os; assert os.path.exists('/work/driver.py') and os.path.exists('/work/cp.txt')" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: sidecar or $VERSION not ready" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  exit 1
fi
