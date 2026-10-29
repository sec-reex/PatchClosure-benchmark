#!/usr/bin/env bash
# reset.sh — down --volumes + up with the same published ports; re-run setup wizard.
set -euo pipefail
: "${COMPOSE_PROJECT_NAME:?}" "${VERSION:?}" "${RUN_FLAG:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
PY="${PCB_PYTHON:-python3}"
if [[ -n "${WORK_DIR:-}" && -d "$WORK_DIR/pydeps" ]]; then
  export PYTHONPATH="$WORK_DIR/pydeps${PYTHONPATH:+:$PYTHONPATH}"
fi
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
ok=0
for _ in $(seq 1 90); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$VERSION" 3001 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]] && curl -sf -o /dev/null --max-time 3 "http://127.0.0.1:${hp}/"; then
    ok=1
    break
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "reset: $VERSION HTTP never ready on published 3001 (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
export PCB_TARGET_PORT="$hp"
if ! "$PY" "$CASE_DIR/poc/seed_exec.py" --bootstrap "$VERSION"; then
  echo "reset: setup wizard / monitor seed failed on 127.0.0.1:${hp}" >&2
  exit 1
fi
echo "reset: $VERSION ready on 127.0.0.1:${hp} (setup wizard done, flag monitor seeded)"
