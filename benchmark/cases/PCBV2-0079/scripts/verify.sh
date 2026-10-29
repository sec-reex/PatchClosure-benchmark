#!/usr/bin/env bash
# verify.sh (PCBV2-0079 apache-struts-cve-2021-31805)
#   seed    : id attribute double-eval (CVE-2020-17530/S2-061), prop="%{#pcbflag}"
#   residual: name attribute nameValue re-eval (CVE-2021-31805/S2-062), prop="#pcbflag"
# Exit: 0=effect 10=blocked 20=env 30=usage
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

if [[ "$MODE" == "--seed" ]]; then
  "$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" > "$WORK_DIR/cand.json" 2>/dev/null \
    || "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json" 2>/dev/null \
    || { echo "original_poc.py 生成 candidate 失败" >&2; exit 20; }
else
  cat > "$WORK_DIR/cand.json" <<'JSON'
{"id": "cve-2021-31805-name-namevalue-reeval", "vector": "name", "prop": "#pcbflag"}
JSON
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

ready=0
for _ in $(seq 1 90); do
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/eval.action" || true)"
  if [[ "$code" == "200" ]]; then ready=1; break; fi
  sleep 2
done
if [[ "$ready" != "1" ]]; then
  echo "verify: /eval.action not ready on :$PORT" >&2
  exit 20
fi

export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"
export PCB_X="$RUN_FLAG"
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
sys.exit(0 if d.get('X') == '$RUN_FLAG' else 10)" "$OUT"
