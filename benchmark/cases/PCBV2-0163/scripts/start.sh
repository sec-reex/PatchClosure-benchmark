#!/usr/bin/env bash
# start.sh — compose up the versioned Maven-jar sink + victim/callback/grid;
# wait until app :80, victim :8070, callback :9000, and grid /status answer
# (readiness: none). Persist PORT_* so reset/verify reuse the same published ports.
# Do not prune networks on shared gpu1. --pull never so compose does not race a
# just-built pcb-owasp-sanitizer tag or re-pull selenium after Maven Built.
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
  printf 'PORT_VICTIM_0=%s\n' "${PORT_VICTIM_0:?}"
  printf 'PORT_CALLBACK_0=%s\n' "${PORT_CALLBACK_0:?}"
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0 PORT_VICTIM_0 PORT_CALLBACK_0
export PCB_FLAG="$RUN_FLAG"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

for other in v0 v1 v2; do
  if [[ "$other" != "$VERSION" ]]; then
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$other" stop "$other" >/dev/null 2>&1 || true
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$other" rm -f "$other" >/dev/null 2>&1 || true
  fi
done

# Official tags only. Maven builder is the Dockerfile FROM (Central resolve happens in build).
docker pull python:3.12-slim >/dev/null 2>&1 || true
docker pull python:3.12-alpine >/dev/null 2>&1 || true
docker pull selenium/standalone-chromium:4.25.0-20240922 >/dev/null 2>&1 || true
docker pull maven:3.9-eclipse-temurin-11 >/dev/null 2>&1 || true

ok_build=0
for i in 1 2 3 4 5; do
  if dc build "$VERSION"; then
    ok_build=1
    break
  fi
  echo "start: maven image build retry $i" >&2
  sleep $((6 * i))
done
if [[ "$ok_build" != "1" ]]; then
  echo "start: docker compose build failed for $VERSION (Maven Central owasp-java-html-sanitizer)" >&2
  exit 1
fi

ok_up=0
for i in 1 2 3 4 5; do
  if dc up -d --build --remove-orphans --pull never; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i (keeping sidecars)" >&2
  dc up -d --build --no-deps --pull never "$VERSION" || true
  if docker inspect "${COMPOSE_PROJECT_NAME}-${VERSION}-1" >/dev/null 2>&1 \
     || [[ -n "$(dc ps -q "$VERSION" 2>/dev/null || true)" ]]; then
    echo "start: compose up rc!=0 but $VERSION is up; continuing" >&2
    ok_up=1
    break
  fi
  sleep $((4 * i))
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  dc ps -a >&2 || true
  dc logs --tail 40 "$SVC" >&2 || true
  exit 1
fi

_port_of() {
  local svc="$1" cport="$2" hp=""
  case "$svc" in
    v0) hp="${PORT_V0_0:-}";;
    v1) hp="${PORT_V1_0:-}";;
    v2) hp="${PORT_V2_0:-}";;
    victim) hp="${PORT_VICTIM_0:-}";;
    callback) hp="${PORT_CALLBACK_0:-}";;
  esac
  if [[ -n "$hp" ]]; then
    echo "$hp"
    return 0
  fi
  dc port "$svc" "$cport" 2>/dev/null \
    | sed 's/.*://' | tr -d '[:space:]' || true
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

ok=0
app_hp="" vic_hp="" cb_hp=""
for i in $(seq 1 180); do
  app_hp="$(_port_of "$SVC" 80)"
  vic_hp="$(_port_of victim 8070)"
  cb_hp="$(_port_of callback 9000)"
  if [[ -n "$app_hp" && -n "$vic_hp" && -n "$cb_hp" ]] \
     && curl -fsS --max-time 5 "http://127.0.0.1:${app_hp}/health" >/dev/null 2>&1 \
     && curl -fsS --max-time 5 "http://127.0.0.1:${vic_hp}/health" >/dev/null 2>&1 \
     && curl -fsS --max-time 5 "http://127.0.0.1:${cb_hp}/health" >/dev/null 2>&1 \
     && _grid_ready; then
    ok=1
    break
  fi
  if [[ "$i" == "40" || "$i" == "90" ]]; then
    dc up -d --no-deps --pull never browser victim >/dev/null 2>&1 || true
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: services never ready app=${app_hp:-none} victim=${vic_hp:-none} callback=${cb_hp:-none}" >&2
  dc ps -a >&2 || true
  dc logs --tail 80 "$SVC" >&2 || true
  dc logs --tail 40 victim >&2 || true
  dc logs --tail 20 browser >&2 || true
  exit 1
fi
echo "start: $SVC ready app=127.0.0.1:${app_hp} victim=${vic_hp} callback=${cb_hp} (owasp-java-html-sanitizer)"
