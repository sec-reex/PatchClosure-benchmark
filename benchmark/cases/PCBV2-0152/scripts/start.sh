#!/usr/bin/env bash
# start.sh — real Next.js (npm next@pin). Wait on published :3000.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"

mkdir -p "$WORK_DIR"
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
if [[ -n "$PORTS" ]]; then export $PORTS; printf '%s\n' $PORTS > "$WORK_DIR/compose.env"; fi
export PCB_FLAG="$RUN_FLAG"

ok_up=0
for i in 1 2 3; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  sleep 8
done
[[ "$ok_up" == "1" ]] || { echo "start: compose up failed" >&2; exit 1; }

svcs=()
if [[ "$VERSION" == "v0" ]]; then
  svcs=(v0)
elif [[ "$VERSION" == "v1" ]]; then
  svcs=(v1_web v1_turbo)
else
  svcs=(v2_turbo)
fi

for svc in "${svcs[@]}"; do
  hp=""; ok=0
  for _ in $(seq 1 90); do
    hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$svc" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
    if [[ -n "$hp" ]]; then
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/admin" || true)"
      if [[ "$code" =~ ^(200|401|403|404)$ ]]; then
        ok=1
        break
      fi
    fi
    sleep 2
  done
  if [[ "$ok" != "1" ]]; then
    echo "start: $svc not ready on ${hp:-none}" >&2
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$svc" >&2 || true
    exit 1
  fi
  echo "start: $svc ready on 127.0.0.1:${hp}"
done
