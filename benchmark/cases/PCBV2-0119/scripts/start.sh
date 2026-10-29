#!/usr/bin/env bash
# start.sh — compose up official GLPI tarball image; wait until CLI install is done.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
# shellcheck disable=SC1091
source "$CASE_DIR/scripts/glpi_ready.sh"

[[ -f "$CASE_DIR/srccache/glpi-10.0.12.tgz" || "$VERSION" != "v0" ]] || {
  echo "start: missing srccache/glpi-10.0.12.tgz (fetch_source first)" >&2
  exit 1
}
[[ -f "$CASE_DIR/srccache/glpi-10.0.14.tgz" || "$VERSION" != "v1" ]] || {
  echo "start: missing srccache/glpi-10.0.14.tgz (fetch_source first)" >&2
  exit 1
}

glpi_assign_ports
export PCB_FLAG="$RUN_FLAG"

ok_up=0
for i in 1 2 3; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi

hp=""
if ! hp="$(wait_glpi_ready)"; then
  echo "start: $VERSION GLPI not ready (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "start: $VERSION ready on 127.0.0.1:${hp} (GLPI install complete)"
