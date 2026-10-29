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
mkdir -p "$WORK_DIR"
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build
hp=""
for _ in $(seq 1 60); do
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$VERSION" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$hp" ]] && curl -fsS --max-time 3 "http://127.0.0.1:${hp}/" >/dev/null 2>&1; then
    break
  fi
  hp=""
  sleep 1
done
[[ -n "$hp" ]] || { echo "start: $VERSION never ready" >&2; exit 1; }
printf 'PCB_TARGET_PORT=%s\n' "$hp" > "$WORK_DIR/compose.env"
echo "start: $VERSION ready on 127.0.0.1:${hp}"
