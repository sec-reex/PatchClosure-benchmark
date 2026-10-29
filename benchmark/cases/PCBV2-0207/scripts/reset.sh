#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same ports; wait until TWiki CGI answers.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/pcb_ports.env" ]]; then
  # shellcheck disable=SC2046
  export $(grep -E '^PORT_' "$WORK_DIR/pcb_ports.env" | xargs)
fi
export PCB_FLAG="$RUN_FLAG"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d

ok=0
hp=""
for _ in $(seq 1 90); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    for path in /bin/view /bin/login; do
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}${path}" || true)"
      if [[ "$code" =~ ^(200|301|302|401|403)$ ]]; then
        echo "reset: TWiki $VERSION ready on :$hp ($path http $code)"
        ok=1
        break 2
      fi
    done
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: TWiki $VERSION did not answer /bin/view or /bin/login (host=$hp)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
