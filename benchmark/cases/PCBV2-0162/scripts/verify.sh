#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# seed: CVE-2022-47951 claimed-vmdk monolithicFlat (poc/original_poc.py)
# residual: CVE-2024-40767 same VMDK bytes, claim=raw (inline; never heldout)
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

APP_PORT="$(dc port "$VERSION" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$APP_PORT" ]]; then
  echo "verify: cannot resolve ${VERSION}:8080 (need --profile)" >&2
  exit 20
fi
export PCB_TARGET_PORT="$APP_PORT"

ready=0
for _ in $(seq 1 60); do
  if curl -fsS --max-time 5 "http://127.0.0.1:${APP_PORT}/healthz" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then echo "verify: ${VERSION} /healthz timeout" >&2; exit 20; fi

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'claim': 'vmdk', 'extent': '/canary/secret.txt'}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
else
  # CVE-2024-40767 residual (inline, never heldout, never seed fallback):
  # same monolithicFlat VMDK bytes, Glance-claimed disk_format=raw.
  printf '%s' '{"probe_id":"cve-2024-40767-vmdk-claimed-raw","claim":"raw","extent":"/canary/secret.txt"}' > "$WORK_DIR/cand.json"
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
