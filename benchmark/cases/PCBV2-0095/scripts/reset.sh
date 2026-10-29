#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait + re-seed flag.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
# shellcheck disable=SC1091
source "$CASE_DIR/scripts/de_ready.sh"

if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
export PCB_FLAG="$RUN_FLAG"

if ! compose_up_profile; then
  echo "reset: compose up failed for profile $VERSION" >&2
  _dc logs --tail 40 "dataease_${VERSION}" >&2 || true
  exit 1
fi

hp=""
if ! hp="$(wait_dataease_ready)"; then
  echo "reset: $VERSION /de2api/login/localLogin never answered (host=${hp:-none})" >&2
  _dc ps >&2 || true
  _dc logs --tail 80 "dataease_${VERSION}" >&2 || true
  exit 1
fi
if ! seed_flag_dashboard; then
  echo "reset: flag dashboard seed failed" >&2
  _dc logs --tail 40 "dataease_${VERSION}" >&2 || true
  exit 1
fi
echo "reset: $VERSION ready on 127.0.0.1:${hp} (flag dashboard planted)"
