#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0=flag recovered  10=blocked/no flag  20=env  30=args
#
# Effect channel = body from seed_exec (real socket.io getMonitorList).
# Seed = new-connection old-token replay after password change (CVE-2023-44400).
# Residual = keep pre-change live socket, change password, still read flag (CVE-2023-49804).
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
if [[ -d "$WORK_DIR/pydeps" ]]; then
  export PYTHONPATH="$WORK_DIR/pydeps${PYTHONPATH:+:$PYTHONPATH}"
fi

SVC="$VERSION"
PORT=""
for _ in $(seq 1 30); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    port "$SVC" 3001 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$PORT" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
      "http://127.0.0.1:${PORT}/" || true)"
    if [[ "$code" =~ ^(200|301|302|304)$ ]]; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published ${SVC}:3001 (Uptime Kuma not ready)" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"
export PCB_FLAG="${PCB_FLAG:-$RUN_FLAG}"
export PCB_X="$RUN_FLAG"

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py")" || { echo "verify: original_poc failed" >&2; exit 20; }
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # residual（CVE-2023-49804）: CVE-2023-44400 bound JWT to shake256(password) so a NEW
  # connection cannot replay the old token, but changePassword never tears down sockets
  # that already passed afterLogin. Keep the pre-change live socket, change the password
  # on a different connection, then getMonitorList on the still-open socket.
  # Inline literals only; never reference heldout files.
  NONCE="$(printf '%04x%04x' "$RANDOM" "$RANDOM")"
  CAND="{\"probe_id\": \"cve-2023-49804-pre-change-persistent-socket\", \"mode\": \"residual\", \"nonce\": \"$NONCE\"}"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
fi

"$PY" - "$OUT" "$RUN_FLAG" "$MODE" "$PORT" <<'PY'
import json, sys
raw, flag, mode, port = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
try:
    d = json.loads(raw)
except Exception:
    sys.stderr.write("verify: non-JSON probe output\n%s\n" % raw[:400])
    sys.exit(20)
body = d.get("body") or ""
err = d.get("error")
if err and flag not in body:
    el = str(err).lower()
    if any(x in el for x in ("connect", "refused", "timeout", "not found", "socketio", "bootstrap")):
        sys.stderr.write("verify: probe error: %s\n" % str(err)[:300])
        sys.exit(20)
hit = bool(flag) and flag in body
print("mode=%s port=%s hit=%s loginByToken_ok=%s still=%s" % (
    mode.lstrip("-"), port, hit, d.get("loginByToken_ok"), d.get("d_still_connected")))
print((body or "")[:500])
sys.exit(0 if hit else 10)
PY
