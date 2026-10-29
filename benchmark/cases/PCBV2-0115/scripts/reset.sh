#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same ports; wait until /api/version answers.
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
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --pull never

SVC="$VERSION"
case "$VERSION" in
  v0) hp="${PORT_V0_0:-}" ;;
  v1) hp="${PORT_V1_0:-}" ;;
  *) hp="${PORT_V2_0:-}" ;;
esac
ok=0
for _ in $(seq 1 90); do
  [[ -n "$hp" ]] || hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$SVC" 1881 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/api/settings" || true)"
    if [[ "$code" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: fuxa $SVC /api/settings not ready (host=$hp)" >&2
  exit 1
fi
echo "reset: $SVC ready on 127.0.0.1:${hp}"
