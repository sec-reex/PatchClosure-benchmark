#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait for login.
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
# Image already has the SuiteCRM tree; never rebuild during reset (600s platform cap).
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --no-build --pull never

ok=0
hp=""
restarts=0
# 280 * 3s = 840s wall, but silent install on a cached image is usually <3 min.
for i in $(seq 1 280); do
  cid="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -aq "$VERSION" 2>/dev/null | head -1 || true)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" || "$status" == "dead" ]]; then
      echo "reset: SuiteCRM $VERSION $status; logs:" >&2
      docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
      if (( restarts < 2 )); then
        restarts=$((restarts + 1))
        echo "reset: compose up --no-build ($restarts/2)" >&2
        docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --no-build --pull never || true
        sleep 5
        continue
      fi
      exit 1
    fi
    hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
    if [[ -n "$hp" ]]; then
      if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" exec -T "$VERSION" test -f /tmp/pcb_ready 2>/dev/null; then
        body="$(curl -sS -m 8 "http://127.0.0.1:${hp}/index.php?module=Users&action=Login" || true)"
        if printf '%s' "$body" | grep -q 'user_name' && ! printf '%s' "$body" | grep -qi 'SilentInstall'; then
          ok=1
          break
        fi
      fi
    fi
  fi
  sleep 3
done
if [[ "$ok" != "1" ]]; then
  echo "reset: SuiteCRM $VERSION login page not ready on published :80 (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 160 "$VERSION" >&2 || true
  exit 1
fi
echo "reset: $VERSION SuiteCRM login ready on 127.0.0.1:${hp}"
