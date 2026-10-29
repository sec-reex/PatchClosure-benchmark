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
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
SVC="wp-${VERSION}"
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT="${PORT_WP_V0_0:-}";;
    v1) PORT="${PORT_WP_V1_0:-}";;
    v2) PORT="${PORT_WP_V2_0:-}";;
  esac
fi
[[ -n "$PORT" ]] || { echo "ERR: cannot resolve WordPress host port for $SVC" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"
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
  # residual：CVE-2026-11962 —— CVE-2024-7985 修复只给 elFinder `upload` 加了文件类型校验
  # （upload.presave）；同权限 subscriber 改走未校验的写操作：mkfile 建 .php（无类型检查）+
  # put 写入 shell body（无检查）→ GET /pcb_bypass.php 执行 → 读出 /flag/pcb_flag.txt。
  CAND='{"probe_id": "cve-2026-11962-elfinder-mkfile-put-php", "op": "mkfile_put", "filename": "pcb_bypass.php"}'
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
