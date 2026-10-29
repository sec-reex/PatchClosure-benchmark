#!/usr/bin/env bash
# start.sh — official LibreChat via compose profile; wait on published :3080
# until register/login works, then return ready.
# Overlay extract flakes: restore pin tags, then `up --pull never` so compose
# does not re-hit ghcr mid-trial.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="$VERSION"
# shellcheck disable=SC1091
source "$CASE_DIR/.source.env"

mkdir -p "$WORK_DIR"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
if [[ -z "${PORT_V0_0:-}" || -z "${PORT_V1_0:-}" || -z "${PORT_V2_0:-}" ]]; then
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
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0
export PCB_FLAG="$RUN_FLAG"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

restore_img() {
  local official="$1" pin="$2"
  if docker image inspect "$official" >/dev/null 2>&1; then
    docker tag "$official" "$pin" >/dev/null 2>&1 || true
    return 0
  fi
  if docker image inspect "$pin" >/dev/null 2>&1; then
    docker tag "$pin" "$official"
    echo "start: restored $official from $pin" >&2
    return 0
  fi
  echo "start: missing $official (fetch_source should have pulled it)" >&2
  return 1
}

ensure_images() {
  local ref=""
  case "$VERSION" in
    v0) ref="${V0:?}" ;;
    v1) ref="${V1:?}" ;;
    v2) ref="v0.8.4-rc1" ;;
    *) echo "start: bad VERSION=$VERSION" >&2; return 1 ;;
  esac
  restore_img "${IMAGE:?}:${ref}" "pcb-0136-librechat:${ref}"
  restore_img "mongo:7.0" "pcb-0136-mongo:7.0"
}

for other in v0 v1 v2; do
  if [[ "$other" != "$VERSION" ]]; then
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$other" stop "$other" >/dev/null 2>&1 || true
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$other" rm -f "$other" >/dev/null 2>&1 || true
  fi
done

ensure_images || exit 1

ok_up=0
for i in 1 2 3; do
  ensure_images || true
  if dc up -d --pull never; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  dc down --volumes --remove-orphans >/dev/null 2>&1 || true
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 40 "$SVC" >&2 || true
  exit 1
fi

hp=""
ok=0
for _ in $(seq 1 120); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$SVC" 3080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/" || true)"
    if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then
      # Homepage answering is enough here; register/login below is the real ready gate.
      # Do not POST /api/auth/login in this tight loop — LOGIN_MAX is IP-wide.
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: $SVC never answered on published :3080 (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi

reg_ok=0
for i in 1 2 3 4 5 6; do
  curl -sS --max-time 15 -H 'Content-Type: application/json' \
    -d '{"name":"pcbready","email":"ready@pcb.local","password":"PcbPass123!","confirm_password":"PcbPass123!"}' \
    "http://127.0.0.1:${hp}/api/auth/register" >/dev/null 2>&1 || true
  tok="$(curl -sS --max-time 15 -H 'Content-Type: application/json' \
    -d '{"email":"ready@pcb.local","password":"PcbPass123!"}' \
    "http://127.0.0.1:${hp}/api/auth/login" || true)"
  if grep -q '"token"' <<<"$tok"; then
    reg_ok=1
    break
  fi
  echo "start: register/login retry $i" >&2
  sleep 5
done
if [[ "$reg_ok" != "1" ]]; then
  echo "start: registration never ready on 127.0.0.1:${hp}" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
echo "start: $SVC ready on 127.0.0.1:${hp} (registration ok)"
