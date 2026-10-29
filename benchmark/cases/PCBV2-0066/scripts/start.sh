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
mkdir -p "$WORK_DIR"
if [[ -n "$PORTS" ]]; then printf '%s\n' $PORTS > "$WORK_DIR/compose.env"; fi
export PCB_FLAG="$RUN_FLAG"
UP_ARGS=(up -d --no-build)
img="pcbv2-0066-antisamy:1.6.5"
[[ "$VERSION" == "v1" ]] && img="pcbv2-0066-antisamy:1.6.6"
[[ "$VERSION" == "v2" ]] && img="pcbv2-0066-antisamy:1.6.7"
if ! docker image inspect "$img" >/dev/null 2>&1; then
  UP_ARGS=(up -d --build)
fi
ok_up=0
for i in 1 2 3; do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" "${UP_ARGS[@]}"; then
    ok_up=1
    break
  fi
  echo "start: compose up retry $i" >&2
  sleep 8
done
[[ "$ok_up" == "1" ]] || { echo "start: compose up failed" >&2; exit 1; }

hp=""
ok=0
for i in $(seq 1 120); do
  if [[ $((i % 15)) -eq 0 ]]; then
    docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" up -d --no-build >/dev/null 2>&1 || true
  fi
  hp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  vp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port victim 8070 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  cp="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" port callback 9000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$hp" && -n "$vp" && -n "$cp" ]] \
     && curl -fsS -m 4 "http://127.0.0.1:${hp}/health" >/dev/null 2>&1 \
     && curl -fsS -m 4 "http://127.0.0.1:${vp}/health" >/dev/null 2>&1 \
     && curl -fsS -m 4 "http://127.0.0.1:${cp}/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 2
done
if [[ "$ok" != "1" ]]; then
  echo "start: $VERSION app/victim/callback not healthy (app=${hp:-none})" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" ps >&2 || true
  exit 1
fi
echo "start: $VERSION AntiSamy ready on 127.0.0.1:${hp}"
