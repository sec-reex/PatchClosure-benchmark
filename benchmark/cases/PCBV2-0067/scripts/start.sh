#!/usr/bin/env bash
# start.sh — compose up the versioned remoting TCP server and wait until :9009 accepts.
# readiness: none (9009 is TCP, host port is ${PORT_V*_0}).
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

img="pcb/jenkins-remoting-tcp:2.52"
[[ "$VERSION" == "v1" ]] && img="pcb/jenkins-remoting-tcp:2.53"
[[ "$VERSION" == "v2" ]] && img="pcb/jenkins-remoting-tcp:3.16"
need_build=0
docker image inspect "$img" >/dev/null 2>&1 || need_build=1
docker image inspect pcb/jenkins-remoting-tcp:client >/dev/null 2>&1 || need_build=1
if [[ "$need_build" == "1" ]]; then
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" --profile client build
fi

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
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi

hp=""
ok=0
for _ in $(seq 1 90); do
  cid="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps -aq "$SVC" 2>/dev/null | head -1 || true)"
  if [[ -n "$cid" ]]; then
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo unknown)"
    if [[ "$status" == "exited" ]]; then
      echo "start: $SVC exited before TCP 9009 was ready" >&2
      docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 160 "$SVC" >&2 || true
      exit 1
    fi
  fi
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$SVC" 9009 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" ]]; then
    if python3 -c "import socket,sys; s=socket.create_connection(('127.0.0.1', int(sys.argv[1])), 2); s.close()" "$hp" 2>/dev/null; then
      ok=1
      break
    fi
  fi
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" exec -T "$SVC" \
       bash -c 'echo >/dev/tcp/127.0.0.1/9009' >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: $SVC not accepting TCP on 9009 (host=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 160 "$SVC" >&2 || true
  exit 1
fi
echo "start: $SVC remoting TCP ready (9009, host=${hp:-in-container})"
