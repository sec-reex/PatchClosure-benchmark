#!/usr/bin/env bash
# start.sh — compose up real pyLoad; inject RUN_FLAG as PCB_FLAG.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
PORTS="$(python3 - <<'PY'
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
print(' '.join(out))
PY
)"
if [[ -n "$PORTS" ]]; then export $PORTS; fi
export PCB_FLAG="$RUN_FLAG"
if [[ -n "$PORTS" ]]; then
  printf '%s\n' $PORTS > "$WORK_DIR/pcb_ports.env"
fi
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build
# Wait for the real web UI (any HTTP response). No wizard.
for _ in $(seq 1 90); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$VERSION" 8000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${hp}/" || true)"
    if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then
      echo "start: $VERSION pyload ready on :$hp (http $code)"
      exit 0
    fi
  fi
  sleep 2
done
echo "start: compose up ok but web UI not yet answering (platform readiness will retry)" >&2
exit 0
