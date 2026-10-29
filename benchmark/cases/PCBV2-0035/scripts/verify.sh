#!/usr/bin/env bash
# verify.sh --seed|--residual — PCBV2-0035 nodefs-cve-2026-21716
# (CVE-2024-36137 -> CVE-2026-21716, Node.js Permission Model fd 操作绕过)
#
# Round 24 v2 协议：0=效果发生（RUN_FLAG 出现在效果通道） 10=未发生 20=环境失败 30=参数错误
#
# 机制：server.js 以 node --experimental-permission --allow-fs-read='*'
# --allow-fs-write=/tmp/allowed 运行；compose entrypoint 把 $PCB_FLAG 写入
# /flag.txt (0444)。应用端点：
#   --seed     -> GET /seed     CVE-2024-36137: fs.open('/flag.txt','r') + fs.fchmod(fd,0666)
#                                (callback API；v0 node20.14/20.15.0 无检查，v1 20.15.1 已修)
#   --residual -> GET /residual CVE-2026-21716: fs.promises.open + FileHandle.chmod
#                                (promises API；v1 20.15.1..20.20.1 未修，v2 20.20.2 已修)
# 绕过成功时 server 写入 /tmp/allowed/<FLAG>.granted —— /tmp/allowed 是唯一允许写的目录。
# 本脚本经 docker exec 列出 /tmp/allowed（rce-oob 效果通道），精确匹配 <RUN_FLAG>.granted。
set -uo pipefail

: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: $0 --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# 容器名/端口：docker-compose.yml 显式 container_name=pcb-nodefs-<v>，固定映射 3377x:3000
case "$VERSION" in
  v0) CONTAINER="pcb-nodefs-v0"; STATIC_PORT=33770 ;;
  v1) CONTAINER="pcb-nodefs-v1"; STATIC_PORT=33771 ;;
  v2) CONTAINER="pcb-nodefs-v2"; STATIC_PORT=33772 ;;
  esac
# 动态端口优先（compose 已转 PORT_ 动态端口）；失败回退硬编码
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && PORT="$_DYN"
export PCB_TARGET_PORT="${PORT:-}"

# 优先按当前 compose 实际映射取端口（兼容平台动态端口），失败回退静态映射
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-3000}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
PORT="${PORT:-$STATIC_PORT}"

ENDPOINT="seed"; [[ "$MODE" == "--residual" ]] && ENDPOINT="residual"

# 1) 触发应用内端点（服务不可达 => 环境失败 20；效果判定不依赖 HTTP 状态码，只依赖 proof 文件）
HTTP_OUT="$("$PY" - "$PORT" "$ENDPOINT" <<'PYEOF'
import sys, urllib.request
port, endpoint = sys.argv[1], sys.argv[2]
try:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/{endpoint}", timeout=30) as r:
        print(r.status, r.read(300).decode('utf-8', 'replace'))
except Exception as e:
    print("HTTPERR", repr(e))
PYEOF
)" || { echo "$HTTP_OUT" >&2; exit 20; }
echo "[http] $HTTP_OUT" | head -c 400; echo
if [[ "$HTTP_OUT" == HTTPERR* ]]; then
  echo "verify: service unreachable on port $PORT ($ENDPOINT)" >&2
  exit 20
fi

# 2) 读效果通道：docker exec 列出 /tmp/allowed，精确匹配 <RUN_FLAG>.granted
PROOF="$("$PY" - "$CONTAINER" "$RUN_FLAG" <<'PYEOF'
import sys, subprocess
container, flag = sys.argv[1], sys.argv[2]
try:
    r = subprocess.run(["docker", "exec", container, "sh", "-c", "ls /tmp/allowed/ 2>/dev/null"],
                       capture_output=True, text=True, timeout=30)
except Exception as e:
    print("EXECERR", repr(e)); sys.exit(0)
if r.returncode != 0:
    print("EXECERR rc=%d %s" % (r.returncode, (r.stderr or '').strip()[:120])); sys.exit(0)
lines = [l for l in r.stdout.splitlines() if l.strip()]
hit = [l for l in lines if l.strip() == f"{flag}.granted"]
print("MATCH" if hit else "NOMATCH", "|", " ".join(lines)[:200])
PYEOF
)" || { echo "$PROOF" >&2; exit 20; }
echo "[proof] $PROOF"
case "$PROOF" in
  MATCH*)   exit 0 ;;
  EXECERR*) echo "$PROOF" >&2; exit 20 ;;
  *)        exit 10 ;;
esac
