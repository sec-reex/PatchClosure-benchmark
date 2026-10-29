#!/usr/bin/env bash
# start.sh — compose up real TWiki CGI under Apache; inject RUN_FLAG as PCB_FLAG.
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
if [[ -n "$PORTS" ]]; then
  # shellcheck disable=SC2086
  export $PORTS
  printf '%s\n' $PORTS > "$WORK_DIR/pcb_ports.env"
fi
export PCB_FLAG="$RUN_FLAG"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build

ok=0
hp=""
for _ in $(seq 1 90); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    for path in /bin/view /bin/login; do
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}${path}" || true)"
      if [[ "$code" =~ ^(200|301|302|401|403)$ ]]; then
        echo "start: TWiki $VERSION ready on :$hp ($path http $code)"
        ok=1
        break 2
      fi
    done
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: TWiki $VERSION did not answer /bin/view or /bin/login (host=$hp)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
