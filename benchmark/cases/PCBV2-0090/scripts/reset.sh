#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait until GraphQL answers.
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

ok=0
hp=""
for _ in $(seq 1 360); do
  cid="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -aq "$VERSION" 2>/dev/null | head -1 || true)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" ]]; then
      echo "reset: Craft $VERSION exited before GraphQL was ready" >&2
      docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 120 "$VERSION" >&2 || true
      exit 1
    fi
    hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
    if [[ -n "$hp" ]]; then
      body="$(curl -s -m 20 -X POST "http://127.0.0.1:${hp}/index.php?p=actions/graphql/api" \
        -H 'Content-Type: application/json' \
        -H 'Authorization: Bearer pcb_gql_token_ssrf_toctou_0001' \
        -d '{"query":"{ ping }"}' 2>/dev/null || true)"
      if printf '%s' "$body" | grep -qE '"ping"[[:space:]]*:[[:space:]]*"pong"'; then
        ok=1
        break
      fi
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: Craft $VERSION GraphQL not ready on published :80 (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 120 "$VERSION" >&2 || true
  exit 1
fi
echo "reset: $VERSION Craft GraphQL ready on 127.0.0.1:${hp}"
