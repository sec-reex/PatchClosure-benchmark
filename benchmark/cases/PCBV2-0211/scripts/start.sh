#!/usr/bin/env bash
# start.sh — 启动 compose 并把 RUN_FLAG 注入目标。平台注入 RUN_ID/COMPOSE_PROJECT_NAME/RUN_FLAG/VERSION/WORK_DIR。
set -euo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CASE_DIR"
# 为每个 PORT_<svc>_<idx> 变量分配高位随机端口（compose 插值；无则跳过）
PORTS="$(python3 - <<'PY'
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
print(' '.join(out))
PY
)"
if [[ -n "$PORTS" ]]; then export $PORTS; fi  # 注意：不能带引号（多变量 word-split）
export PCB_FLAG="$RUN_FLAG"
# Build the versioned client image; only persist the internal sidecars.
# client-* is an ephemeral `compose run` probe (CMD would exit immediately).
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" build
docker compose -p "$COMPOSE_PROJECT_NAME" up -d --no-build redirector attacker
# Wait until both sidecars accept TCP :80 (compose up -d is not "listening").
ok=0
for _ in $(seq 1 40); do
  if docker compose -p "$COMPOSE_PROJECT_NAME" exec -T redirector \
       python -c "import socket; s=socket.create_connection(('127.0.0.1',80),2); s.close()" \
     && docker compose -p "$COMPOSE_PROJECT_NAME" exec -T attacker \
       python -c "import socket; s=socket.create_connection(('127.0.0.1',80),2); s.close()"; then
    ok=1
    break
  fi
  sleep 1
done
if [[ "$ok" != "1" ]]; then
  echo "start: sidecars did not accept :80" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" ps >&2 || true
  exit 1
fi
