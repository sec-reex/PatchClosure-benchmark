#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait for reinstall.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
# shellcheck disable=SC1091
source "$CASE_DIR/scripts/glpi_ready.sh"

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
if ! hp="$(wait_glpi_ready)"; then
  echo "reset: $VERSION GLPI not ready (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "reset: $VERSION ready on 127.0.0.1:${hp}"
