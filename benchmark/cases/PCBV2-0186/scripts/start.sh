#!/usr/bin/env bash
# start.sh — official apache/rocketmq NameServer; wait until remoting TCP is up.
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
mkdir -p "$WORK_DIR"
if [[ -n "$PORTS" ]]; then printf '%s\n' $PORTS > "$WORK_DIR/compose.env"; fi
export PCB_FLAG="$RUN_FLAG"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d

SVC="namesrv-${VERSION}"
ok=0
hp=""
for _ in $(seq 1 90); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" port "$SVC" 9876 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]] && PYTHONPATH="$CASE_DIR" python3 -c "
import socket, sys
port = int(sys.argv[1])
try:
    s = socket.create_connection(('127.0.0.1', port), 2)
    s.close()
except OSError:
    raise SystemExit(1)
from rocketmq_remoting import get_namesrv_config
r = get_namesrv_config('127.0.0.1', port, timeout=3)
raise SystemExit(0 if r.get('code') == 0 else 1)
" "$hp" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: namesrv $SVC not accepting remoting on TCP 9876 (host=$hp)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" logs --tail 80 "$SVC" >&2 || true
  exit 1
fi
echo "start: $SVC ready on 127.0.0.1:${hp}"
