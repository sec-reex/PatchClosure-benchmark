#!/usr/bin/env bash
# verify.sh --seed|--residual — deser_mina_objser
# (CVE-2024-52046 type-1 seed / CVE-2026-42779 type-0 residual).
#
# Effect channel = TCP echo of /canary/flag.txt (PCB_FLAG) after PcbSeed.readObject().
#   seed     mode=type1  (normal MINA type-1 descriptor)
#              v0(2.2.3) no accept() API -> reconstructs -> flag echoed rc=0
#              v1(2.2.6) allowlist in resolveClass non-null branch -> blocked rc=10
#   residual mode=type0  (forced 0x00 / null-clazz descriptor)
#              v1(2.2.6) null-clazz branch skips allowlist -> flag echoed rc=0
# Residual candidate is an inline literal (never references heldout files).
# Exit: 0=effect 10=blocked 20=env 30=args
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
export PCB_FLAG="$RUN_FLAG"
export PCB_X="$RUN_FLAG"

# Dynamic host port (compose interpolates PORT_*); seed_exec does not need it
# (client talks service-name:9009 on the compose network).
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-9009}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"

if [[ "$MODE" == "--seed" ]]; then
  "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json"
else
  # residual: same PcbSeed class, type-0/null-clazz wire encoding (CVE-2026-42779)
  printf '%s' '{"id": "cve-2026-42779-type0-null-clazz-bypass", "mode": "type0"}' > "$WORK_DIR/cand.json"
fi

OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c 'import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
sys.exit(0 if d.get("X") == sys.argv[2] else 10)' "$OUT" "$RUN_FLAG"
rc=$?
echo "verify[$MODE] version=$VERSION rc=$rc" >&2
exit "$rc"
