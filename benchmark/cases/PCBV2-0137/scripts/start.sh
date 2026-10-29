#!/usr/bin/env bash
# start.sh — official LibreChat via compose profile; wait on published :3080
# until register/login works, then return ready.
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

for other in v0 v1 v2; do
  if [[ "$other" != "$VERSION" ]]; then
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$other" stop "$other" >/dev/null 2>&1 || true
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$other" rm -f "$other" >/dev/null 2>&1 || true
  fi
done

ok_up=0
for i in 1 2 3; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d; then
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

hp=""
ok=0
for _ in $(seq 1 120); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$SVC" 3080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${hp}/" || true)"
    if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then
      # API is up once login returns a real HTTP status (401/400/429 all fine).
      acode="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
        -H 'Content-Type: application/json' \
        -d '{"email":"ready@pcb.local","password":"PcbPass123!"}' \
        "http://127.0.0.1:${hp}/api/auth/login" || true)"
      if [[ "$acode" =~ ^[1-5][0-9][0-9]$ ]]; then
        ok=1
        break
      fi
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
