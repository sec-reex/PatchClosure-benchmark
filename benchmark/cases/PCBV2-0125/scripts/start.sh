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
# 植入 per-run flag 到 Loki ruler 组名（oracle plant_flag 语义：组名=flag，路径遍历读取）
if [[ -n "$RUN_FLAG" ]]; then
  cat > "$CASE_DIR/_run/pcb_flag.yaml" <<PLANT
groups:
  - name: $RUN_FLAG
    rules:
      - alert: PcbCanary
        expr: 'count_over_time({job="pcb"}[5m]) > 0'
        for: 1m
        labels:
          severity: info
        annotations:
          summary: pcb canary
PLANT
fi
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --build
