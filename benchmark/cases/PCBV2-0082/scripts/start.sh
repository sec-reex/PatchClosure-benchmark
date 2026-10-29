#!/usr/bin/env bash
# start.sh — reuse pcb-avideo-real:$VERSION; `up --pull never`; retry create/network;
# wait on the published compose host port (not a hardcoded :80).
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="$VERSION"
export COMPOSE_PARALLEL_LIMIT=1

# Drop leftover controller PORT_* from a prior case. Only this run's compose.env counts.
unset PORT_V0_0 PORT_V1_0 PORT_V2_0 PORT_CALLBACK_0 PORT_VICTIM_0
mkdir -p "$WORK_DIR"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

_write_env() {
  {
    printf 'PORT_V0_0=%s\n' "${PORT_V0_0:?}"
    printf 'PORT_V1_0=%s\n' "${PORT_V1_0:?}"
    printf 'PORT_V2_0=%s\n' "${PORT_V2_0:?}"
    printf 'PORT_CALLBACK_0=%s\n' "${PORT_CALLBACK_0:?}"
    printf 'PORT_VICTIM_0=%s\n' "${PORT_VICTIM_0:?}"
  } > "$WORK_DIR/compose.env"
  export PORT_V0_0 PORT_V1_0 PORT_V2_0 PORT_CALLBACK_0 PORT_VICTIM_0
}

_alloc_ports() {
  eval "$(python3 - <<'PY'
import os, re, random
text = open('docker-compose.yml').read()
names = sorted(set(re.findall(r'\$\{PORT_([A-Za-z0-9_]+):-', text)))
used = set()
out = []
for n in names:
    key = f'PORT_{n}'
    # Force a fresh set when called after a bind/network clash.
    while True:
        p = random.randint(20000, 59999)
        if p not in used:
            used.add(p)
            out.append(f'{key}={p}')
            break
print('\n'.join(out))
PY
)"
  _write_env
}

if [[ -z "${PORT_V0_0:-}" || -z "${PORT_V1_0:-}" || -z "${PORT_V2_0:-}" \
   || -z "${PORT_CALLBACK_0:-}" || -z "${PORT_VICTIM_0:-}" ]]; then
  _alloc_ports
else
  _write_env
fi
export PCB_FLAG="$RUN_FLAG"

dc() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    --profile "$VERSION" "$@"
}

_compose_err_one_line() {
  local log="$1" line=""
  line="$(grep -iE 'Error|error|failed|conflict|denied|Pool overlaps|already allocated|already exists|address already in use' "$log" 2>/dev/null \
    | grep -viE '^(#[0-9]| Container | Network | Volume | Image )' \
    | tail -3 | tr '\n' ';' | head -c 240 || true)"
  if [[ -z "$line" && -f "$log" ]]; then
    line="$(tail -c 240 "$log" | tr '\n' ' ')"
  fi
  printf '%s' "$line"
}

ensure_image() {
  local img="$1" i
  if docker image inspect "$img" >/dev/null 2>&1; then
    return 0
  fi
  echo "start: pulling $img" >&2
  for i in 1 2 3 4 5; do
    if timeout 180 docker pull "$img"; then
      return 0
    fi
    echo "start: pull $img retry $i" >&2
    sleep $((8 * i))
  done
  echo "start: pull $img failed" >&2
  return 1
}

# Official / already-local tags only. Never pull mcr.microsoft.com (hangs on gpu1).
# pcb-avideo-real:* and pcb-avideo-victim:se425 are built below, never pulled from Hub.
ensure_image "python:3.12-alpine" || exit 1
ensure_image "python:3.12-slim" || exit 1
if docker image inspect "selenium/standalone-chromium:latest" >/dev/null 2>&1; then
  echo "start: reusing selenium/standalone-chromium:latest" >&2
elif docker image inspect "selenium/standalone-chromium:4.25.0-20240922" >/dev/null 2>&1; then
  docker tag "selenium/standalone-chromium:4.25.0-20240922" "selenium/standalone-chromium:latest"
else
  ensure_image "selenium/standalone-chromium:latest" || exit 1
fi
ensure_image "php:8.3-cli" || exit 1

VIMG="pcb-avideo-victim:se425"
if docker image inspect "$VIMG" >/dev/null 2>&1; then
  echo "start: reusing $VIMG" >&2
else
  echo "start: building $VIMG (selenium client)" >&2
  ok_v=0
  for i in 1 2 3; do
    if dc build victim; then
      ok_v=1
      break
    fi
    echo "start: victim image build retry $i" >&2
    sleep $((8 * i))
  done
  if [[ "$ok_v" != "1" ]]; then
    echo "start: docker compose build failed for $VIMG" >&2
    exit 1
  fi
fi

IMG="pcb-avideo-real:${VERSION}"
if docker image inspect "$IMG" >/dev/null 2>&1; then
  echo "start: reusing $IMG" >&2
else
  echo "start: building $IMG (full WWBN/AVideo clone)" >&2
  ok_build=0
  for i in 1 2 3; do
    if dc build "$SVC"; then
      ok_build=1
      break
    fi
    echo "start: image build retry $i" >&2
    sleep $((10 * i))
  done
  if [[ "$ok_build" != "1" ]]; then
    echo "start: docker compose build failed for $IMG" >&2
    exit 1
  fi
fi

for other in v0 v1 v2; do
  if [[ "$other" != "$VERSION" ]]; then
    docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
      --profile "$other" stop "$other" >/dev/null 2>&1 || true
    docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
      --profile "$other" rm -f "$other" >/dev/null 2>&1 || true
  fi
done

log="${WORK_DIR}/compose_up_${VERSION}.log"
ok_up=0
for i in 1 2 3 4 5; do
  if dc up -d --no-build --pull never --remove-orphans >"$log" 2>&1; then
    ok_up=1
    break
  fi
  cid="$(dc ps -q "$SVC" 2>/dev/null || true)"
  if [[ -n "$cid" ]]; then
    echo "start: compose up rc!=0 but $SVC exists; continuing" >&2
    ok_up=1
    break
  fi
  echo "start: compose create retry $i $(_compose_err_one_line "$log")" >&2
  if grep -qiE 'address already in use|port is already allocated' "$log"; then
    echo "start: host port clash — reallocating PORT_*" >&2
    _alloc_ports
  fi
  if grep -qiE 'Pool overlaps|failed to create network|network .* already exists' "$log"; then
    echo "start: compose network clash — dropping leftover default net" >&2
    docker network rm "${COMPOSE_PROJECT_NAME}_default" >/dev/null 2>&1 || true
  fi
  dc down --remove-orphans >/dev/null 2>&1 || true
  sleep $((5 * i + RANDOM % 4))
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION: $(_compose_err_one_line "$log")" >&2
  dc ps -a >&2 || true
  dc logs --tail 40 "$SVC" >&2 || true
  exit 1
fi

_port_of() {
  local svc="$1" cport="$2"
  dc port "$svc" "$cport" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true
}

hp=""; vic=""; cb=""
ok=0
for n in $(seq 1 90); do
  cid="$(dc ps -q "$SVC" 2>/dev/null || true)"
  if [[ -z "$cid" ]]; then
    echo "start: $SVC missing — re-up ($n)" >&2
    dc up -d --no-build --pull never >/dev/null 2>&1 || true
    sleep 2
    continue
  fi
  status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo missing)"
  if [[ "$status" != "running" ]]; then
    echo "start: $SVC status=$status — re-up ($n)" >&2
    dc up -d --no-build --pull never >/dev/null 2>&1 || true
    sleep 2
    continue
  fi
  hp="$(_port_of "$SVC" 80)"
  vic="$(_port_of victim 8070)"
  cb="$(_port_of callback 9000)"
  if [[ -n "$hp" && -n "$vic" && -n "$cb" ]]; then
    acode="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/" || true)"
    vhealth="$(curl -sS --max-time 5 "http://127.0.0.1:${vic}/health" || true)"
    chealth="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${cb}/health" || true)"
    if [[ "$acode" == "200" && "$vhealth" == "ok" && "$chealth" == "200" ]]; then
      ok=1
      break
    fi
  fi
  if [[ "$n" == "20" || "$n" == "45" ]]; then
    dc up -d --no-deps --no-build --pull never browser victim callback >/dev/null 2>&1 || true
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: $SVC never became ready on published ports (app=${hp:-none} victim=${vic:-none} cb=${cb:-none})" >&2
  dc ps -a >&2 || true
  dc logs --tail 80 "$SVC" >&2 || true
  dc logs --tail 40 victim >&2 || true
  exit 1
fi

# Persist the *published* host ports (platform may remap; never assume :80).
case "$VERSION" in
  v0) PORT_V0_0="$hp" ;;
  v1) PORT_V1_0="$hp" ;;
  v2) PORT_V2_0="$hp" ;;
esac
PORT_VICTIM_0="$vic"
PORT_CALLBACK_0="$cb"
_write_env

# Prove the running tree is the WWBN/AVideo clone (not a raw-file splice).
echo "start: clone proof (must be real /app from git checkout):"
dc exec -T "$SVC" \
  sh -c 'test -f /app/objects/functionsSecurity.php && test -f /app/vendor/erusev/parsedown/Parsedown.php && echo "files=ok" && git -C /app rev-parse HEAD && git -C /app remote get-url origin && git -C /app log -1 --oneline' \
  || { echo "start: clone proof failed" >&2; exit 1; }

echo "start: $SVC ready on 127.0.0.1:${hp} (victim :${vic} callback :${cb})"
