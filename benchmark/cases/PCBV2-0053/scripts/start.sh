#!/usr/bin/env bash
# start.sh — compose up AntiSamy + victim/callback/grid; persist compose.env;
# wait until app/callback/victim /health AND compose-internal grid /status answer.
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
  printf 'PORT_CALLBACK_0=%s\n' "${PORT_CALLBACK_0:?}"
  printf 'PORT_VICTIM_0=%s\n' "${PORT_VICTIM_0:?}"
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0 PORT_CALLBACK_0 PORT_VICTIM_0
export PCB_FLAG="$RUN_FLAG"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

# Build the versioned AntiSamy image first so `up` is not a build+create race.
dc build "$SVC" || true

# Never `down` between retries — that kills a healthy grid and restarts pip.
# --pull never: do not try docker.io/pcb-antisamy-comment (access denied) and
# do not lose a just-built tag to a concurrent prune/pull.
ok_up=0
for i in 1 2 3; do
  if dc up -d --build --remove-orphans --pull never; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i (keeping sidecars)" >&2
  dc logs --tail 40 >&2 || true
  dc up -d --build --no-deps --pull never "$SVC" || true
  if dc ps -a --format '{{.Name}} {{.Service}}' 2>/dev/null | grep -q " ${SVC}$" \
     || docker inspect "${COMPOSE_PROJECT_NAME}-${SVC}-1" >/dev/null 2>&1; then
    ok_up=1
    break
  fi
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  dc logs --tail 80 >&2 || true
  exit 1
fi
if ! docker inspect "${COMPOSE_PROJECT_NAME}-${SVC}-1" >/dev/null 2>&1; then
  echo "start: $SVC missing after up; rebuilding locally" >&2
  dc up -d --build --no-deps --pull never "$SVC" || true
fi

_port_of() {
  local svc="$1" cport="$2"
  dc port "$svc" "$cport" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true
}

# Probe the compose-internal grid only (no host :4444). callback has Python.
_grid_ready() {
  dc exec -T callback \
    python3 -c "import urllib.request; urllib.request.urlopen('http://browser:4444/status', timeout=5).read()" \
    >/dev/null 2>&1 \
  || dc exec -T callback \
    python3 -c "import urllib.request; urllib.request.urlopen('http://browser:4444/wd/hub/status', timeout=5).read()" \
    >/dev/null 2>&1
}

_running() {
  local svc="$1" status
  status="$(docker inspect -f '{{.State.Status}}' "${COMPOSE_PROJECT_NAME}-${svc}-1" 2>/dev/null || echo missing)"
  [[ "$status" == "running" ]]
}

ok=0
app=""; cb=""; vic=""
for _ in $(seq 1 180); do
  app="$(_port_of "$SVC" 80)"
  cb="$(_port_of callback 9000)"
  vic="$(_port_of victim 8070)"
  if [[ -n "$app" && -n "$cb" && -n "$vic" ]] \
     && _running "$SVC" && _running callback && _running victim && _running browser \
     && curl -fsS --max-time 5 "http://127.0.0.1:${app}/health" >/dev/null 2>&1 \
     && curl -fsS --max-time 5 "http://127.0.0.1:${cb}/health" >/dev/null 2>&1 \
     && curl -fsS --max-time 5 "http://127.0.0.1:${vic}/health" >/dev/null 2>&1 \
     && _grid_ready; then
    ok=1
    break
  fi
  # Victim /health is 503 until grid is up; restart a dead sidecar.
  if ! _running browser || ! _running victim; then
    dc up -d browser victim >/dev/null 2>&1 || true
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: antisamy stack not ready (app=${app:-none} cb=${cb:-none} vic=${vic:-none})" >&2
  dc ps >&2 || true
  dc logs --tail 80 >&2 || true
  exit 1
fi
# Chromium/victim can flap after first /status. Re-check and bring the
# versioned app back too (trial-2 v1 died here with app= empty).
_stack_ok() {
  app="$(_port_of "$SVC" 80)"
  cb="$(_port_of callback 9000)"
  vic="$(_port_of victim 8070)"
  [[ -n "$app" && -n "$cb" && -n "$vic" ]] \
    && _running "$SVC" && _running callback && _running victim && _running browser \
    && curl -fsS --max-time 5 "http://127.0.0.1:${app}/health" >/dev/null 2>&1 \
    && curl -fsS --max-time 5 "http://127.0.0.1:${cb}/health" >/dev/null 2>&1 \
    && curl -fsS --max-time 5 "http://127.0.0.1:${vic}/health" >/dev/null 2>&1 \
    && _grid_ready
}
sleep 8
if ! _stack_ok; then
  echo "start: health flapped after settle; restarting app+sidecars" >&2
  dc up -d --no-deps --pull never "$SVC" callback browser victim >/dev/null 2>&1 || true
  settled=0
  for _ in $(seq 1 40); do
    if _stack_ok; then
      settled=1
      break
    fi
    sleep 2
  done
  if [[ "$settled" != "1" ]]; then
    echo "start: stack still down after restart (app=${app:-none} cb=${cb:-none} vic=${vic:-none})" >&2
    dc ps -a >&2 || true
    dc logs --tail 80 >&2 || true
    exit 1
  fi
fi
{
  printf 'PUBLISHED_PORT=%s\n' "$app"
  printf 'PUBLISHED_CB=%s\n' "$cb"
  printf 'PUBLISHED_VIC=%s\n' "$vic"
} >> "$WORK_DIR/compose.env"
echo "start: $SVC ready on 127.0.0.1:${app} (cb :${cb} vic :${vic})"
