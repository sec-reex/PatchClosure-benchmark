#!/usr/bin/env bash
# start.sh — compose up the npm-installed @adobe/css-tools Express service + watchdog;
# wait until GET /health answers on the published host port (readiness: none).
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="$VERSION"

mkdir -p "$WORK_DIR"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
eval "$(python3 - <<'PY'
import os, re, random
text = open('docker-compose.yml').read()
names = sorted(set(re.findall(r'\$\{PORT_([A-Za-z0-9_]+):-', text)))
used = set()
for n in names:
    cur = os.environ.get(f'PORT_{n}')
    if cur and cur.isdigit():
        used.add(int(cur))
out = []
for n in names:
    key = f'PORT_{n}'
    if os.environ.get(key):
        continue
    while True:
        p = random.randint(20000, 59999)
        if p not in used:
            used.add(p)
            out.append(f'{key}={p}')
            break
print('\n'.join(out))
PY
)"
{
  printf 'PORT_V0_0=%s\n' "${PORT_V0_0:?}"
  printf 'PORT_V1_0=%s\n' "${PORT_V1_0:?}"
  printf 'PORT_V2_0=%s\n' "${PORT_V2_0:?}"
  printf 'PORT_WATCHDOG_0=%s\n' "${PORT_WATCHDOG_0:?}"
} > "$WORK_DIR/compose.env"
printf '%s' "$RUN_FLAG" > "$WORK_DIR/planted.flag"
export PORT_V0_0 PORT_V1_0 PORT_V2_0 PORT_WATCHDOG_0
export PCB_FLAG="$RUN_FLAG"
export VERSION

for other in v0 v1 v2; do
  if [[ "$other" != "$VERSION" ]]; then
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$other" stop "$other" >/dev/null 2>&1 || true
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$other" rm -f "$other" >/dev/null 2>&1 || true
  fi
done

ok_up=0
for i in 1 2 3; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build --force-recreate; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 40 "$SVC" >&2 || true
  exit 1
fi

_port_of() {
  local svc="$1" cport="$2"
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$svc" "$cport" 2>/dev/null \
    | sed 's/.*://' | tr -d '[:space:]' || true
}

ok=0
hp="" wd=""
for _ in $(seq 1 90); do
  hp="$(_port_of "$SVC" 3000)"
  wd="$(_port_of watchdog 8888)"
  if [[ -n "$hp" && -n "$wd" ]] \
     && curl -fsS --max-time 5 "http://127.0.0.1:${hp}/health" >/dev/null 2>&1 \
     && curl -fsS --max-time 5 "http://127.0.0.1:${wd}/status" >/dev/null 2>&1; then
    streak="$(curl -sS --max-time 5 "http://127.0.0.1:${wd}/status" 2>/dev/null \
      | python3 -c "import json,sys
try:
    print(int(json.load(sys.stdin).get('dbg',{}).get('ok_streak',0)))
except Exception:
    print(0)" 2>/dev/null || echo 0)"
    if [[ "${streak:-0}" -ge 3 ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: $SVC /health or watchdog baseline never ready app=${hp:-none} wd=${wd:-none}" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 40 watchdog >&2 || true
  exit 1
fi
# Persist the actually published ports (compose interpolation can differ from the pre-up draw).
{
  printf 'PORT_V0_0=%s\n' "${PORT_V0_0}"
  printf 'PORT_V1_0=%s\n' "${PORT_V1_0}"
  printf 'PORT_V2_0=%s\n' "${PORT_V2_0}"
  printf 'PORT_WATCHDOG_0=%s\n' "${wd}"
  case "$VERSION" in
    v0) printf 'PORT_V0_0=%s\n' "${hp}" ;;
    v1) printf 'PORT_V1_0=%s\n' "${hp}" ;;
    v2) printf 'PORT_V2_0=%s\n' "${hp}" ;;
  esac
} > "$WORK_DIR/compose.env"
echo "start: $SVC ready on 127.0.0.1:${hp} watchdog=${wd} (npm @adobe/css-tools GET /health)"
