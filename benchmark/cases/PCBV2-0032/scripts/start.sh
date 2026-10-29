#!/usr/bin/env bash
# start.sh — compose up the CPAN DBI profile; wait until perl -MDBI -e1 works.
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
mkdir -p "$WORK_DIR"
{
  [[ -n "$PORTS" ]] && printf '%s\n' $PORTS
} > "$WORK_DIR/compose.env"
export PCB_FLAG="$RUN_FLAG"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build

ok=0
for _ in $(seq 1 60); do
  CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -q "$VERSION" 2>/dev/null | head -1 | tr -d '[:space:]')"
  if [[ -n "$CID" ]] \
     && docker exec "$CID" perl -MDBI -e1 >/dev/null 2>&1 \
     && docker exec "$CID" test -s /pcb_flag.txt >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: $VERSION not ready (perl -MDBI /pcb_flag.txt)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "start: $VERSION ready (perl -MDBI -e1)"
