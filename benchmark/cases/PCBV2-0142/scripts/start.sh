#!/usr/bin/env bash
# start.sh — compose up the VERSION profile; persist published ports; wait until
# app / victim / callback answer (selenium grid + pip install can be slow).
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
if [[ -z "${PORT_V0_0:-}" || -z "${PORT_V1_0:-}" || -z "${PORT_V2_0:-}" \
   || -z "${PORT_CALLBACK_0:-}" || -z "${PORT_VICTIM_0:-}" ]]; then
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
  printf 'PORT_CALLBACK_0=%s\n' "${PORT_CALLBACK_0}"
  printf 'PORT_VICTIM_0=%s\n' "${PORT_VICTIM_0}"
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0 PORT_CALLBACK_0 PORT_VICTIM_0
export PCB_FLAG="$RUN_FLAG"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

# Pre-pull official tags only. Never prune networks on this shared gpu1 host.
# --pull never on `up` so compose does not race a just-built pcb-loofah-svg tag.
docker pull python:3.12-slim >/dev/null 2>&1 || true
docker pull python:3.12-alpine >/dev/null 2>&1 || true
docker pull selenium/standalone-chromium:4.25.0-20240922 >/dev/null 2>&1 || true
dc build "$VERSION" || true

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
  exit 1
fi

_dcport() { dc port "$1" "$2" 2>/dev/null | awk -F: 'NR==1{gsub(/[[:space:]]/,"",$NF); print $NF}' || true; }
_running() {
  local status
  status="$(docker inspect -f '{{.State.Status}}' "${COMPOSE_PROJECT_NAME}-${1}-1" 2>/dev/null || echo missing)"
  [[ "$status" == "running" ]]
}

ok=0
hp=""
for i in $(seq 1 180); do
  hp="$(_dcport "$VERSION" 80)"
  vic="$(_dcport victim 8070)"
  cb="$(_dcport callback 9000)"
  if [[ -n "$hp" && -n "$vic" && -n "$cb" ]] \
     && _running "$VERSION" && _running victim && _running callback && _running browser; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/" || true)"
    vhealth="$(curl -s --max-time 5 "http://127.0.0.1:${vic}/health" || true)"
    chealth="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${cb}/dump" || true)"
    if [[ "$code" == "200" && "$vhealth" == "ok" && "$chealth" == "200" ]]; then
      ok=1
      break
    fi
  fi
  if [[ "$i" == "40" || "$i" == "90" ]]; then
    dc up -d --no-deps --pull never browser victim >/dev/null 2>&1 || true
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: $VERSION not ready (host=${hp:-none})" >&2
  dc ps -a >&2 || true
  dc logs --tail 80 "$VERSION" >&2 || true
  dc logs --tail 40 victim >&2 || true
  dc logs --tail 20 browser >&2 || true
  exit 1
fi
echo "start: $VERSION ready on 127.0.0.1:${hp} victim=${vic} callback=${cb}"
