#!/usr/bin/env bash
# reset.sh — down + up --pull never with the same published ports; wait on compose port.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="$VERSION"
unset PORT_V0_0 PORT_V1_0 PORT_V2_0 PORT_CALLBACK_0 PORT_VICTIM_0
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
export PCB_FLAG="$RUN_FLAG"
export COMPOSE_PARALLEL_LIMIT=1

dc() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    --profile "$VERSION" "$@"
}

dc down --volumes --remove-orphans >/dev/null 2>&1 || true
ok_up=0
for i in 1 2 3; do
  if dc up -d --no-build --pull never --remove-orphans; then
    ok_up=1
    break
  fi
  echo "reset: compose up retry $i" >&2
  dc down --remove-orphans >/dev/null 2>&1 || true
  sleep $((4 * i))
done
if [[ "$ok_up" != "1" ]]; then
  echo "reset: compose up failed for $VERSION" >&2
  exit 1
fi

ok=0
hp=""
for _ in $(seq 1 90); do
  hp="$(dc port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  vic="$(dc port victim 8070 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  cb="$(dc port callback 9000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" && -n "$vic" && -n "$cb" ]]; then
    acode="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/" || true)"
    vhealth="$(curl -sS --max-time 5 "http://127.0.0.1:${vic}/health" || true)"
    chealth="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${cb}/health" || true)"
    if [[ "$acode" == "200" && "$vhealth" == "ok" && "$chealth" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $SVC did not become ready (host=${hp:-none})" >&2
  dc ps >&2 || true
  dc logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
echo "reset: $VERSION ready on 127.0.0.1:${hp}"
