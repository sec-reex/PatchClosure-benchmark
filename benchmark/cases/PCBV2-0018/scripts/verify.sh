#!/usr/bin/env bash
# verify.sh --seed|--residual — gitea sibling endpoint 越权读。
# 判定：probe ok AND status==200 AND 真 flag 短 token(flag_token(RUN_FLAG_REF)) 在响应。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
# Leftover org/token from seed can crash a second setup. wrong/stale reject here.
if [[ -n "${RUN_FLAG_REF:-}" && "$RUN_FLAG" != "$RUN_FLAG_REF" ]]; then
  echo "status=rejected(wrong/stale flag)"
  exit 10
fi
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
REF="${RUN_FLAG_REF:-$RUN_FLAG}"
PORT=""
for _ in $(seq 1 30); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" \
    port "$VERSION" 3000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$PORT" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${PORT}/user/login" || true)"
    if [[ "$code" == "200" ]]; then
      break
    fi
  fi
  sleep 1
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published $VERSION:3000" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"
PROBE="seed_probe"; [[ "$MODE" == "--residual" ]] && PROBE="residual_probe"

OUT="$("$PY" - "$VERSION" "$RUN_FLAG" "$REF" "$PROBE" <<PYEOF
import sys, json
sys.path.insert(0, '$CASE_DIR/poc')
import gitea_util as g
r = getattr(g, sys.argv[4])(sys.argv[1], sys.argv[2])
ref_tok = g.flag_token(sys.argv[3])
print(json.dumps({**r, 'ref_tok': ref_tok}, default=str))
PYEOF
)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
d = json.loads(sys.argv[1])
ok = bool(d.get('ok')) and d.get('status') == 200 and d.get('ref_tok') in str(d.get('body','')).lower()
sys.exit(0 if ok else 10)" "$OUT"
