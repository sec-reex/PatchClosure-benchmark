#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same ports; wait /health; replant flag.
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
dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }
dc down --volumes --remove-orphans >/dev/null 2>&1 || true
dc up -d

SVC="$VERSION"
ok=0
hp=""
for _ in $(seq 1 90); do
  hp="$(dc port "$SVC" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/health" || true)"
    if [[ "$code" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: gotenberg $SVC did not answer /health (host=$hp)" >&2
  dc ps >&2 || true
  dc logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
dc exec -T "$SVC" sh -c "printf '%s\n' \"$RUN_FLAG\" > /tmp/pcb_flag.txt" || {
  echo "reset: could not plant /tmp/pcb_flag.txt in $SVC" >&2
  exit 1
}
dc exec -u root -T "$SVC" sh -c "printf '%s\n' \"$RUN_FLAG\" > /pcb_flag.txt" >/dev/null 2>&1 || true
echo "reset: $SVC ready on 127.0.0.1:${hp}"
