#!/usr/bin/env bash
# verify.sh --seed|--residual — astro-cve-2026-59729（SSR 属性名 XSS，xss-echo）
#
# 机制：probe server（server.js）调用 REAL Astro SSR 渲染函数，注入的属性名
# `x" data-pcb="<FLAG>` 内嵌 /flag.txt 中的 flag（compose entrypoint 从 $PCB_FLAG 植入）：
#   GET /seed     -> addAttribute('v', key)        : V0(6.4.5) 属性名未转义直接插入 HTML
#                    输出含 flag；V1(7.0.4) CVE-2026-54298 修复（INVALID_ATTR_NAME_CHAR
#                    守卫）丢弃该 key -> 输出不含 flag。
#   GET /residual -> renderHTMLElement(result, HTMLElement 子类, {[key]:'v'}, {}) :
#                    dom.ts 内联属性循环不走 addAttribute，V1 上守卫未覆盖 -> flag 仍泄漏
#                    （CVE-2026-59729）；V2(7.0.6) 同一守卫补到内联循环 -> 阻断。
# 效果通道 = HTTP 响应 JSON {ok, html, flag}：html 含 RUN_FLAG_REF（或 flag 字段等于它）。
# 退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
FLAG_REF="$RUN_FLAG"
mkdir -p "$WORK_DIR" 2>/dev/null || true

# 动态解析宿主端口（compose 服务名即 v0/v1/v2，容器内端口 3000）
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-3000}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$PORT" ]] || { echo "verify: 无法解析 $VERSION 宿主端口（容器未运行？）" >&2; exit 20; }

# 就绪等待：node probe server 冷启动几秒，先等 /health
for _ in $(seq 1 30); do
  if curl -s -o /dev/null -m 2 "http://127.0.0.1:$PORT/health"; then break; fi
  sleep 1
done

# 探测：--seed -> /seed；--residual -> /residual；判定 html 含 flag 或 flag 字段命中
"$PY" - "$PORT" "$FLAG_REF" "$MODE" <<'PYEOF'
import json
import sys
import urllib.request

port, flag, mode = sys.argv[1], sys.argv[2], sys.argv[3]
path = "/seed" if mode == "--seed" else "/residual"
try:
    with urllib.request.urlopen("http://127.0.0.1:%s%s" % (port, path), timeout=30) as r:
        data = json.loads(r.read().decode("utf-8", "replace"))
except Exception as e:
    print("verify: request failed: %r" % (e,), file=sys.stderr)
    sys.exit(20)
html = data.get("html", "") or ""
got = data.get("flag", "") or ""
print("verify[%s]: flag_field=%r html_head=%r" % (mode, got[:40], html[:100]))
if got == flag or flag in html:
    sys.exit(0)
sys.exit(10)
PYEOF
RC=$?
echo "verify[$MODE] version=$VERSION rc=$RC (flag_ref=${FLAG_REF:0:12}...)" >&2
exit "$RC"
