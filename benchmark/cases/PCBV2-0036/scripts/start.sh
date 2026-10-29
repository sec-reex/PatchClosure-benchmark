#!/usr/bin/env bash
# start.sh — official b3log/siyuan; wait published :6806 loginAuth.
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
} > "$WORK_DIR/compose.env"
export PORT_V0_0 PORT_V1_0 PORT_V2_0
export PCB_FLAG="$RUN_FLAG"

case "$VERSION" in
  v0) img="b3log/siyuan:v3.5.9";;
  v1) img="b3log/siyuan:v3.5.10";;
  v2) img="b3log/siyuan:v3.6.5";;
  *) echo "start: unknown VERSION=$VERSION" >&2; exit 1;;
esac

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "$@"; }

if ! docker image inspect "$img" >/dev/null 2>&1; then
  echo "start: pulling $img" >&2
  docker pull "$img"
fi

ok_up=0
for i in 1 2 3 4; do
  if dc up -d; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  dc down --remove-orphans >/dev/null 2>&1 || true
  sleep 6
done
if [[ "$ok_up" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  dc logs --tail 80 "$SVC" >&2 || true
  exit 1
fi

hp=""
ok=0
for _ in $(seq 1 120); do
  cid="$(dc ps -aq "$SVC" 2>/dev/null | head -1 || true)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" || "$status" == "dead" ]]; then
      echo "start: $SVC $status before HTTP ready" >&2
      dc logs --tail 160 "$SVC" >&2 || true
      docker inspect -f '{{.State.ExitCode}} {{.State.Error}}' "$cid" >&2 || true
      exit 1
    fi
  fi
  hp="$(dc port "$SVC" 6806 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
      -H 'Content-Type: application/json' \
      -d '{"authCode":"pcb"}' \
      "http://127.0.0.1:${hp}/api/system/loginAuth" || true)"
    if [[ "$code" == "200" ]]; then
      ok=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: $SVC never answered POST /api/system/loginAuth (host=${hp:-none})" >&2
  dc ps >&2 || true
  dc logs --tail 160 "$SVC" >&2 || true
  exit 1
fi
printf 'PUBLISHED_PORT=%s\n' "$hp" >> "$WORK_DIR/compose.env"
echo "start: $SVC ready on 127.0.0.1:${hp} (official b3log/siyuan)"
