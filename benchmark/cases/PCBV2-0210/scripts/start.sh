#!/usr/bin/env bash
# start.sh — official louislam/uptime-kuma via compose profile; wait until socket.io + setup.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
if [[ -d "$WORK_DIR/pydeps" ]]; then
  export PYTHONPATH="$WORK_DIR/pydeps${PYTHONPATH:+:$PYTHONPATH}"
fi

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
  echo "start: $VERSION HTTP never ready on published 3001 (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi

export PCB_TARGET_PORT="$hp"
if ! "$PY" "$CASE_DIR/poc/seed_exec.py" --bootstrap "$VERSION"; then
  echo "start: setup wizard / monitor seed failed on 127.0.0.1:${hp}" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "start: $VERSION ready on 127.0.0.1:${hp} (setup wizard done, flag monitor seeded)"
