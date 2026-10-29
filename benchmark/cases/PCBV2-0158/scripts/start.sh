#!/usr/bin/env bash
# start.sh — October CMS + mysql; persist published :80; retry compose up.
# Sweep failed when mysql on tmpfs was unhealthy under concurrent load.
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
SVC="$VERSION"
cname="${COMPOSE_PROJECT_NAME}-${SVC}-1"

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
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0
export PCB_FLAG="$RUN_FLAG"

case "$VERSION" in
  v0) hp="${PORT_V0_0}";;
  v1) hp="${PORT_V1_0}";;
  v2) hp="${PORT_V2_0}";;
  *) echo "start: unknown VERSION=$VERSION" >&2; exit 1;;
esac

ok_up=0
for i in 1 2 3 4; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --volumes --remove-orphans >/dev/null 2>&1 || true
  sleep 8
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 db >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 40 "$SVC" >&2 || true
  exit 1
fi

ready=0
for _ in $(seq 1 120); do
  status="$(docker inspect -f '{{.State.Status}}' "$cname" 2>/dev/null || echo missing)"
  if [[ "$status" == "exited" || "$status" == "dead" ]]; then
    echo "start: $SVC exited before HTTP ready (status=$status)" >&2
    docker logs --tail 120 "$cname" >&2 || true
    exit 1
  fi
  if [[ "$status" == "running" ]] \
     && curl -fsS --max-time 5 "http://127.0.0.1:${hp}/" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" != "1" ]]; then
  echo "start: $SVC never answered HTTP on 127.0.0.1:${hp}" >&2
  docker logs --tail 80 "${COMPOSE_PROJECT_NAME}-db-1" >&2 || true
  docker logs --tail 120 "$cname" >&2 || true
  exit 1
fi
printf 'PUBLISHED_PORT=%s\n' "$hp" >> "$WORK_DIR/compose.env"
echo "start: $SVC ready on 127.0.0.1:${hp} (october)"
