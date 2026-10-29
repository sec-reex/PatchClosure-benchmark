#!/usr/bin/env bash
# reset.sh — restore this trial's OFBiz (same ports) and wait for HTTP 8080.
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
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
# Image already has load-data; never rebuild during reset (platform reset timeout is 600s).
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" up -d --no-build --pull never

ok=0
hp=""
# 190 * 3s = 570s, under the 600s platform reset timeout.
for _ in $(seq 1 190); do
  cid="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" ps -aq "$VERSION" 2>/dev/null | head -1)"
  if [[ -z "$cid" ]]; then
    cid="$(docker ps -aq -f "label=com.docker.compose.project=${COMPOSE_PROJECT_NAME}" -f "label=com.docker.compose.service=${VERSION}" 2>/dev/null | head -1 || true)"
  fi
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" ]]; then
      echo "reset: OFBiz $VERSION exited before ready" >&2
      docker logs --tail 80 "$cid" >&2 || true
      exit 1
    fi
    if [[ "$status" == "running" ]]; then
      hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$VERSION" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
      if [[ -n "$hp" ]]; then
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/" || true)"
        if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then
          ok=1
          break
        fi
      fi
    fi
  fi
  sleep 3
done
if [[ "$ok" != "1" ]]; then
  echo "reset: OFBiz $VERSION did not become ready on HTTP 8080 (host=$hp)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "reset: $VERSION OFBiz ready on 127.0.0.1:${hp}"
