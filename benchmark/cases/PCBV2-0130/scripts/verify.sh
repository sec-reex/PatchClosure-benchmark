#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0=flag recovered  10=blocked/no flag  20=env  30=args
#
# Effect channel = recovered_secret / X from seed_exec (external HTTP as attacker,
# then admin /scriptText decrypt). Seed = config.xml READ. Residual = agent COPY.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

SVC="$VERSION"
PORT=""
for _ in $(seq 1 30); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    port "$SVC" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  if [[ -n "$PORT" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
      -u admin:admin123 "http://127.0.0.1:${PORT}/computer/agentA/api/json" || true)"
    if [[ "$code" == "200" ]]; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published ${SVC}:8080 (Jenkins not ready)" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"
export PCB_X="$RUN_FLAG"
export PCB_FLAG="$RUN_FLAG"

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py")" || { echo "verify: original_poc failed" >&2; exit 20; }
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # residual (CVE-2025-31721): V1 2.492.2 redacts config.xml READ but still copies a
  # secret-bearing agent via POST /computer/createItem?mode=copy&from=agentA without
  # Agent/Configure. Then GET the copy's config.xml and decrypt the cipher.
  printf '%s' '{"id":"cve-2025-31721-copy_agent_with_secret","probe":"copy"}' > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
fi

"$PY" - "$OUT" "$RUN_FLAG" "$MODE" "$PORT" <<'PY'
import json, sys
raw, flag, mode, port = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
try:
    d = json.loads(raw)
except Exception:
    sys.stderr.write("verify: non-JSON probe output\n%s\n" % raw[:400])
    sys.exit(20)
if d.get("error") and not (d.get("recovered_secret") or d.get("X")):
    sys.stderr.write("verify: probe error: %s\n" % str(d.get("error"))[:300])
    sys.exit(20)
secret = d.get("recovered_secret") or ""
x = d.get("X") or ""
hit = bool(flag) and (flag in secret or x == flag)
print("mode=%s port=%s status=%s denied=%s cipher=%s hit=%s" % (
    mode.lstrip("-"), port, d.get("http_status"), d.get("denied") or "",
    d.get("cipher_seen") or "", hit))
sys.exit(0 if hit else 10)
PY
