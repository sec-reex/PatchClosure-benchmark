#!/usr/bin/env bash
# start.sh — compose up the gem-installed rack profile; inject RUN_FLAG into
# the watchdog; wait until GET /health and watchdog baseline are ready.
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
if [[ -z "${PORT_V0_0:-}" || -z "${PORT_V1_0:-}" || -z "${PORT_V2_0:-}" || -z "${PORT_WATCHDOG_0:-}" ]]; then
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
  printf 'PORT_WATCHDOG_0=%s\n' "${PORT_WATCHDOG_0}"
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0 PORT_WATCHDOG_0
export PCB_FLAG="$RUN_FLAG"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build

ok=0
hp=""
wd=""
for _ in $(seq 1 180); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$VERSION" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  wd="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port watchdog 8888 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" && -n "$wd" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${hp}/health" || true)"
    wst="$(curl -sS -m 3 "http://127.0.0.1:${wd}/status" 2>/dev/null || true)"
    streak="$(printf '%s' "$wst" | python3 -c "import json,sys
try:
    print(int(json.load(sys.stdin).get('dbg',{}).get('ok_streak',0)))
except Exception:
    print(0)" 2>/dev/null || echo 0)"
    if [[ "$code" == "200" && "$streak" -ge 3 ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: $VERSION not ready (host=${hp:-none} wd=${wd:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$VERSION" >&2 || true
  exit 1
fi
echo "start: $VERSION ready on 127.0.0.1:${hp} watchdog=${wd}"
