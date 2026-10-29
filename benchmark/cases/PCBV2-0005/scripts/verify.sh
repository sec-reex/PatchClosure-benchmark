#!/usr/bin/env bash
# PCBV2-0005 xstream-cve-2020-26217 -- 定制 verify.sh
#
# 机制: REAL XStream new XStream().fromXML(xml) sink (POST /deser, text/xml), 由版本自身的
#       DEFAULT deny-list (XStream.setupSecurity(), 构造器默认应用) 决定 trigger 类型名放行/阻断;
#       放行则继续处理 <pcb.PcbCanary/>, 其 benign converter 读取 /canary/flag.txt,
#       服务在响应体回显 PCB_CANARY_FLAG=<token>。
#   seed    : java.beans.EventHandler (CVE-2013-7285 trigger, 在 1.4.13 deny-list)
#               v0(1.4.10, deny-list 空) -> 放行, flag 回显  rc=0
#               v1(1.4.13, 名单含该名) -> ForbiddenClassException 阻断  rc=10
#   residual: javax.imageio.ImageIO$ContainsFilter (CVE-2020-26217 trigger, 不在 1.4.13 deny-list,
#             1.4.14 才加入)
#               v1(1.4.13, 名单不含) -> 放行, flag 回显 rc=0
#               v2(1.4.14, 名单含) -> 阻断              rc=10
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
  # residual: CVE-2020-26217 trigger 类型名 ('$' 由 seed_exec.py 的 _xml_for 转成 '_-')
  # 写成 JSON 字符串字面量; seed_exec.py run_probe 对非 dict 自动包装为 {"type": ...}
  printf '"%s"' "javax.imageio.ImageIO\$ContainsFilter" > "$WORK_DIR/cand.json"
  probe "$WORK_DIR/cand.json"; rc=$?
fi
echo "verify[$MODE] version=$VERSION rc=$rc (flag_ref=$FLAG_REF)" >&2
exit "$rc"
