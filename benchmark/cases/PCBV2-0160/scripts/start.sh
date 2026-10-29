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
# No long-running HTTP service. `up -d` would one-shot the exploit entrypoint and exit.
# Build the versioned real-OpenSSL image; verify.sh drives `compose run --rm`.
docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" build
IMG="pcb-crehash-real-${VERSION}"
ok=""
for _ in $(seq 1 30); do
  if docker image inspect "$IMG" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
[[ -n "$ok" ]] || { echo "start: image $IMG missing after build" >&2; exit 1; }
# Smoke the real compiled openssl (not the exploit entrypoint).
smoke="$(docker compose -p "$COMPOSE_PROJECT_NAME" --profile "$VERSION" \
  run --rm --no-deps --entrypoint /opt/ossl/bin/openssl "$VERSION" version 2>&1)" || {
  echo "start: openssl not runnable: $smoke" >&2
  exit 1
}
echo "$smoke"
