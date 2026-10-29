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
if [[ -n "$PORTS" ]]; then export $PORTS; fi
mkdir -p "$WORK_DIR"
printf '%s\n' "$PORTS" > "$WORK_DIR/ports.env"
export PCB_FLAG="$RUN_FLAG"
# v0 is a local build (no official pre-27598-fix image); v1/v2 are official pulls.
up_ok=0
for i in 1 2 3; do
  if [[ "$VERSION" == "v0" ]]; then
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build && up_ok=1 && break
  else
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d && up_ok=1 && break
  fi
  echo "start: compose up retry $i" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" down --remove-orphans || true
  sleep 8
done
if [[ "$up_ok" != "1" ]]; then
  echo "start: compose up failed for profile $VERSION" >&2
  exit 1
fi
