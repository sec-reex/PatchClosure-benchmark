#!/usr/bin/env bash
# PCBV2-0004 jackson-databind-cve-2018-5968 -- 定制 verify.sh
#
# 机制: REAL jackson-databind default-typing 反序列化 sink (POST /deser, body=["<FQCN>",{}]),
#       由版本自身的 DEFAULT_NO_DESER_CLASS_NAMES 黑名单 (SubTypeValidator.validateSubType,
#       @since 2.8.11) 决定类名放行/阻断; 放行则 benign shadow 类构造器读取 /canary/flag.txt,
#       服务在响应体回显 PCB_CANARY_FLAG=<token>。
#   seed    : org.apache.commons.collections.functors.InvokerTransformer (7525 黑名单名)
#               v0(2.8.8, 无黑名单) -> 实例化, flag 回显  rc=0
#               v1(2.8.11, 名单含该名) -> 阻断           rc=10
#   residual: org.hibernate.jmx.StatisticsService / org.apache.ibatis.datasource.jndi.JndiDataSourceFactory
#             (databind#1899 才加入名单, CVE-2018-5968 修复)
#               v1(2.8.11, 名单不含) -> 实例化, flag 回显 rc=0
#               v2(2.8.11.1, 名单含) -> 阻断              rc=10
# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
CASE_DIR="${CASE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

# flag 通道: HTTP 响应体 (seed_exec.py 的 X 字段 = PCB_X 出现在响应体即命中)
# 判定基准: RUN_FLAG_REF (回退 RUN_FLAG); PCB_X 必须设为 RUN_FLAG_REF 而非 RUN_FLAG
#           (wrong/stale 检查时 RUN_FLAG 是注入容器的 override, 不能作为判定基准)
# 退出码: 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail

: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
FLAG_REF="$RUN_FLAG"
mkdir -p "$WORK_DIR"

# probe <cand.json> : 通过公开执行器 seed_exec.py 探测, 返回 0/10/20
probe() {
  local cand="$1" out rc
  export PCB_X="$FLAG_REF"   # seed_exec.py 模块级 X = PCB_X or PCB_FLAG; 期望 flag 用 RUN_FLAG_REF
  out="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$cand" "$VERSION" 2>&1)" || { echo "seed_exec 失败: $out" >&2; return 20; }
  echo "[probe $VERSION] $out" >&2
  "$PY" -c 'import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
sys.exit(0 if d.get("X") == sys.argv[2] else 10)' "$out" "$FLAG_REF"
  rc=$?
  echo "[probe $VERSION] flag_hit=$FLAG_REF -> rc=$rc" >&2
  return $rc
}

rc=0
if [[ "$MODE" == "--seed" ]]; then
  "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json" 2>/dev/null \
    || { echo "original_poc.py 生成 candidate 失败" >&2; exit 20; }
  probe "$WORK_DIR/cand.json"; rc=$?
else
  # residual: 两个 CVE-2018-5968 gadget FQCN 任一被放行即效果发生 (v1 均不在 2.8.11 名单)
  # 写成 JSON 字符串字面量; seed_exec.py run_probe 对非 dict 自动包装为
  # {"probe_class":..., "json_body":["<FQCN>",{}]}
  for fqcn in \
      "org.hibernate.jmx.StatisticsService" \
      "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory"; do
    printf '"%s"' "$fqcn" > "$WORK_DIR/cand.json"
    probe "$WORK_DIR/cand.json"; rc=$?
    [[ $rc -eq 0 || $rc -eq 20 ]] && break
  done
fi
echo "verify[$MODE] version=$VERSION rc=$rc (flag_ref=$FLAG_REF)" >&2
exit "$rc"
