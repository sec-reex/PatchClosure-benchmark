#!/usr/bin/env bash
# start.sh — reuse local pcb-testlink-real + official tags; `up --pull never`
# so Hub congestion after "Image Built" does not fail compose (sweep flake).
# Do not prune networks on shared gpu1.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"

host_port() {
  # compose port can fail before the mapping exists; never let pipefail kill start.sh.
  docker compose -p "$COMPOSE_PROJECT_NAME" port "$1" "$2" 2>/dev/null \
    | sed -E 's/.*:([0-9]+)$/\1/' | tr -d '[:space:]' | tail -1 || true
}

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
  printf 'PORT_VICTIM_0=%s\n' "${PORT_VICTIM_0:?}"
  printf 'PORT_CALLBACK_0=%s\n' "${PORT_CALLBACK_0:?}"
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0 PORT_VICTIM_0 PORT_CALLBACK_0
export PCB_FLAG="$RUN_FLAG"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

ensure_image() {
  local img="$1"
  if docker image inspect "$img" >/dev/null 2>&1; then
    return 0
  fi
  echo "start: pulling $img" >&2
  local i
  for i in 1 2 3 4 5; do
    if docker pull "$img"; then
      return 0
    fi
    echo "start: pull $img retry $i" >&2
    sleep $((8 * i))
  done
  echo "start: pull $img failed" >&2
  return 1
}

# Official/cached tags only. Local pcb-testlink-real is built below, never pulled.
ensure_image "mariadb:10.6" || exit 1
ensure_image "python:3.12-slim" || exit 1
ensure_image "selenium/standalone-chromium:4.25.0-20240922" || exit 1
ensure_image "php:7.4-apache" || true

APP_IMG="pcb-testlink-real:${VERSION}"
ok_build=0
if docker image inspect "$APP_IMG" >/dev/null 2>&1; then
  echo "start: reusing $APP_IMG" >&2
  ok_build=1
else
  for i in 1 2 3 4 5; do
    if dc build "$VERSION"; then
      ok_build=1
      break
    fi
    echo "start: TestLink image build retry $i" >&2
    sleep $((6 * i))
  done
fi
if [[ "$ok_build" != "1" ]]; then
  echo "start: docker compose build failed for $APP_IMG" >&2
  exit 1
fi

svc_up() {
  docker inspect "${COMPOSE_PROJECT_NAME}-${1}-1" >/dev/null 2>&1 \
    || [[ -n "$(dc ps -q "$1" 2>/dev/null || true)" ]]
}

ok_up=0
for i in 1 2 3 4 5; do
  if dc up -d --remove-orphans --pull never; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i (keeping sidecars)" >&2
  dc up -d --no-deps --pull never "$VERSION" || true
  if svc_up "$VERSION"; then
    echo "start: compose up rc!=0 but $VERSION is up; continuing" >&2
    ok_up=1
    break
  fi
  sleep $((4 * i))
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  dc ps -a >&2 || true
  dc logs --tail 40 "$VERSION" >&2 || true
  exit 1
fi

_grid_ready() {
  dc exec -T callback \
    python3 -c "import urllib.request; urllib.request.urlopen('http://chromium:4444/status', timeout=5).read()" \
    >/dev/null 2>&1 \
  || dc exec -T callback \
    python3 -c "import urllib.request; urllib.request.urlopen('http://chromium:4444/wd/hub/status', timeout=5).read()" \
    >/dev/null 2>&1
}

ok=0
hp="" vp="" cp=""
for i in $(seq 1 180); do
  hp="$(host_port "$VERSION" 80)"
  vp="$(host_port victim 8070)"
  cp="$(host_port callback 9000)"
  if [[ -z "$hp" || -z "$vp" || -z "$cp" ]]; then
    if (( i % 10 == 0 )); then
      echo "start: ports missing (app=$hp victim=$vp callback=$cp), compose up again" >&2
      dc up -d --pull never >/dev/null 2>&1 || true
    fi
  elif [[ -n "$hp" && -n "$vp" && -n "$cp" ]]; then
    acode="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/login.php" || true)"
    vbody="$(curl -s --max-time 5 "http://127.0.0.1:${vp}/health" || true)"
    cbody="$(curl -s --max-time 5 "http://127.0.0.1:${cp}/health" || true)"
    if [[ "$acode" =~ ^[1-5][0-9][0-9]$ && "$vbody" == *"ok"* && "$cbody" == *"ok"* ]] \
       && _grid_ready; then
      ok=1
      break
    fi
  fi
  if [[ "$i" == "40" || "$i" == "90" ]]; then
    dc up -d --no-deps --pull never chromium victim >/dev/null 2>&1 || true
  fi
  sleep 3
done
if [[ "$ok" != "1" ]]; then
  echo "start: TestLink $VERSION not ready (app=$hp victim=$vp callback=$cp)" >&2
  dc ps -a >&2 || true
  dc logs --tail 80 "$VERSION" >&2 || true
  dc logs --tail 40 victim >&2 || true
  dc logs --tail 20 chromium >&2 || true
  exit 1
fi
echo "start: $VERSION TestLink ready on 127.0.0.1:${hp} (victim=${vp} callback=${cp})"
