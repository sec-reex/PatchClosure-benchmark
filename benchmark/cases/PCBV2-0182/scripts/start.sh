#!/usr/bin/env bash
# start.sh — compose up the versioned gem-install sink + victim/callback/grid;
# wait until app :80, victim :8070, callback :9000, and grid /wd/hub/status answer
# (readiness: none). Persist PORT_* so reset/verify reuse the same published ports.
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

for other in v0 v1 v2; do
  if [[ "$other" != "$VERSION" ]]; then
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$other" stop "$other" >/dev/null 2>&1 || true
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$other" rm -f "$other" >/dev/null 2>&1 || true
  fi
done

ok_up=0
for i in 1 2 3; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build; then
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
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$svc" "$cport" 2>/dev/null \
    | sed 's/.*://' | tr -d '[:space:]' || true
}

_grid_ready() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" exec -T browser \
    curl -fsS --max-time 5 http://127.0.0.1:4444/wd/hub/status >/dev/null 2>&1 \
    || docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" exec -T browser \
      curl -fsS --max-time 5 http://127.0.0.1:4444/status >/dev/null 2>&1
}

ok=0
app_hp="" vic_hp="" cb_hp=""
for _ in $(seq 1 120); do
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
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: services never ready app=${app_hp:-none} victim=${vic_hp:-none} callback=${cb_hp:-none}" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 40 victim >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 20 browser >&2 || true
  exit 1
fi
echo "start: $SVC ready app=127.0.0.1:${app_hp} victim=${vic_hp} callback=${cb_hp} (gem rails-html-sanitizer)"
