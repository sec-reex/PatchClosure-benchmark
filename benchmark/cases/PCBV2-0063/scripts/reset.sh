#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; wait for pcb_probe.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="$VERSION"
unset PORT_V0_0 PORT_V1_0 PORT_V2_0
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
export PORT_V0_0 PORT_V1_0 PORT_V2_0
export PCB_FLAG="$RUN_FLAG"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

dc down --volumes --remove-orphans >/dev/null 2>&1 || true
dc up -d

hp=""
ok=0
for _ in $(seq 1 180); do
  cid="$(dc ps -aq "$SVC" 2>/dev/null | head -1 || true)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" ]]; then
      echo "reset: $SVC exited before pcb_probe was ready" >&2
      dc logs --tail 160 "$SVC" >&2 || true
      exit 1
    fi
  fi
  hp="$(dc port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    body="$(curl -sS -m 5 "http://127.0.0.1:${hp}/pcb_probe.php?action=health" || true)"
    if printf '%s' "$body" | grep -qE '"ok"[[:space:]]*:[[:space:]]*true'; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: pcb_probe health not ready on published :80 (host=${hp:-none})" >&2
  dc ps >&2 || true
  dc logs --tail 160 "$SVC" >&2 || true
  exit 1
fi
echo "reset: $SVC Cacti probe ready on 127.0.0.1:${hp}"
