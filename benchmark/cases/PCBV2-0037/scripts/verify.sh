#!/usr/bin/env bash
# verify.sh --seed|--residual — vm2-cve-2026-24120 (PCBV2-0037)
#
# 机制：probe server（server.js）在真实 vm2 沙箱里跑攻击者代码，利用 Promise
#       [@@species] 逃逸拿到宿主 process，执行 `cat /flag.txt > /tmp/pcb_result.txt`
#       （flag 由 compose entrypoint 从 $PCB_FLAG 写入 /flag.txt）。
#   seed     /exploit?kind=37466   Promise species 替换直通逃逸（CVE-2023-37466）
#            V0(3.9.19) 达效果 | V1(3.10.0) resetPromiseSpecies 还原 species -> 阻断
#   residual /exploit?kind=24120   先 Object.defineProperty=()=>{} 废掉
#            resetPromiseSpecies 的还原逻辑再触发逃逸（CVE-2026-24120）
#            V1(3.10.0..3.10.4) 达效果 | V2(3.10.5) 加固 -> 阻断
# 效果通道 = 容器内 /tmp/pcb_result.txt（docker exec 读取，rce-oob）。
# 判定基准 = RUN_FLAG_REF（平台真 flag；wrong/stale 检查时 RUN_FLAG 为 override，
#            判定必须用 RUN_FLAG_REF，回退 RUN_FLAG）。
# 退出码：0=效果发生(flag 出现) 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
FLAG_REF="$RUN_FLAG"
mkdir -p "$WORK_DIR" 2>/dev/null || true

# 目标端口：优先 docker compose port 动态解析，回退 case 固定端口
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-3000}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT=33860;; v1) PORT=33861;; v2) PORT=33862;;
  esac
fi
# 动态端口优先（compose 已转 PORT_ 动态端口）；失败回退硬编码
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && PORT="$_DYN"
export PCB_TARGET_PORT="${PORT:-}"
CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" ps -q "$VERSION" 2>/dev/null | head -1)"
if [[ -z "$CID" ]]; then
  echo "verify: container for $VERSION not running" >&2
  exit 20
fi

# 就绪等待：/health 探活
for _ in $(seq 1 60); do
  if curl -s -o /dev/null -m 3 "http://127.0.0.1:$PORT/health"; then break; fi
  sleep 2
done

KIND=37466
[[ "$MODE" == "--residual" ]] && KIND=24120

# 触发 exploit（HTTP 都连不上 -> 环境失败 20）
curl -s -m 30 "http://127.0.0.1:$PORT/exploit?kind=$KIND" >/dev/null 2>&1 || { echo "verify: exploit http call failed" >&2; exit 20; }
sleep 1

# 效果通道：docker exec 读结果文件（未逃逸时文件不存在 -> 效果未发生 10）
RESULT="$(docker exec "$CID" cat /tmp/pcb_result.txt 2>/dev/null || true)"
echo "[$VERSION kind=$KIND] result_head=${RESULT:0:120}"
if grep -q "$FLAG_REF" <<<"$RESULT"; then
  echo "verify[$MODE] version=$VERSION rc=0 (flag_ref=$FLAG_REF)" >&2
  exit 0
fi
echo "verify[$MODE] version=$VERSION rc=10 (flag_ref=$FLAG_REF)" >&2
exit 10
