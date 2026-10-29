#!/usr/bin/env bash
# start.sh — official daptin/daptin via compose profile; wait on :8080 and seed pcb_canary.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"

mkdir -p "$WORK_DIR"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
if [[ -z "${PORT_V0_0:-}" || -z "${PORT_V1_0:-}" || -z "${PORT_V2_0:-}" ]]; then
  eval "$(python3 - <<'PY'
import re, random
text = open('docker-compose.yml').read()
names = sorted(set(re.findall(r'\$\{PORT_([A-Za-z0-9_]+):-', text)))
used = set()
out = []
for n in names:
    while True:
        p = random.randint(20000, 59999)
        if p not in used:
            used.add(p)
            out.append(f'PORT_{n}={p}')
            break
print('\n'.join(out))
PY
)"
fi
{
  printf 'PORT_V0_0=%s\n' "${PORT_V0_0}"
  printf 'PORT_V1_0=%s\n' "${PORT_V1_0}"
  printf 'PORT_V2_0=%s\n' "${PORT_V2_0}"
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0
export PCB_FLAG="$RUN_FLAG"

ok_up=0
for i in 1 2 3; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 40 "$VERSION" >&2 || true
  exit 1
fi

hp=""
for _ in $(seq 1 90); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$VERSION" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  [[ -n "$hp" ]] && break
  sleep 2
done
[[ -n "$hp" ]] || { echo "start: no published port for $VERSION:8080" >&2; exit 20; }

if ! python3 "$CASE_DIR/scripts/daptin_api.py" wait --base "http://127.0.0.1:${hp}"; then
  echo "start: $VERSION /api/world not ready (host=${hp})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi

cid="$(docker compose -p "$COMPOSE_PROJECT_NAME" ps -q "$VERSION" | head -1)"
[[ -n "$cid" ]] || { echo "start: no container for $VERSION" >&2; exit 20; }

if ! python3 "$CASE_DIR/scripts/daptin_api.py" seed --base "http://127.0.0.1:${hp}" --flag "$RUN_FLAG" --container "$cid"; then
  echo "start: pcb_canary seed failed" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "start: $VERSION ready on 127.0.0.1:${hp} (pcb_canary seeded)"
