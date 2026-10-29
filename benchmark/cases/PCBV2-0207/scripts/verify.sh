#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
#
# seed     = CVE-2009-1339 forged GET  /bin/save (no token). Works on TWiki 4.3.0;
#            blocked post_method_only on 4.3.1.
# residual = CVE-2009-4898 tokenless forged POST /bin/save (V1 requires POST but
#            has no crypt token). Inline literal only — no heldout refs.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
export PCB_FLAG="${PCB_FLAG:-$RUN_FLAG}"
SVC="$VERSION"
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
export PCB_TARGET_PORT="${PORT:-}"
if [[ -z "$PORT" ]]; then
  echo "verify: could not resolve published port for $SVC" >&2
  exit 20
fi

# CGI can still be warming after compose-up; wait for /bin/view or /bin/login.
ready=0
for _ in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/bin/view" || true)"
  code2="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/bin/login" || true)"
  if [[ "$code" =~ ^(200|301|302|401|403)$ || "$code2" =~ ^(200|301|302|401|403)$ ]]; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" != "1" ]]; then
  echo "verify: TWiki CGI not answering on :$PORT" >&2
  exit 20
fi

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'path': s.strip(), 'to': s.strip(), 'payload': s.strip(), 'css': s.strip()}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # CVE-2009-4898: tokenless forged POST /bin/save. V1 (4.3.1) accepts POST
  # without crypttoken; seed GET is blocked. Literal only — no heldout files.
  printf '%s' '{"probe_id":"cve-2009-4898-tokenless-post-save","mode":"residual"}' > "$WORK_DIR/cand.json"
  export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"
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
