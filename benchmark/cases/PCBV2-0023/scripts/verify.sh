#!/usr/bin/env bash
# PCBV2-0023 (admidio-cve-2026-42194) 定制 verify.sh
# 机制：CVE-2026-32812 -> CVE-2026-42194，Admidio SSO-metadata `fetch_metadata.php` SSRF。
#   seed     = https://seed.pcb.test/  （恒解析到内网 canary 10.99.0.192）
#               V0(5.0.6) file_get_contents 无 IP 校验 -> 拿到 ${PCB_FLAG}
#               V1(5.0.7) gethostbyname 判定 private -> IP filter 拦截
#   residual = https://rebind.pcb.test/ （DNS rebind：CHECK 得 decoy 198.51.100.50 公共 IP 放行，
#               cURL FETCH 再解析得 canary）-> V1 上仍 SSRF 拿到 flag（CVE-2026-42194 TOCTOU）。
# 效果通道：HTTP 响应 body（seed_exec.py 输出 JSON 的 fetched_body 字段含 flag）。
# 判定基准：RUN_FLAG_REF（回退 RUN_FLAG）。
# 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
if [[ -n "${RUN_FLAG_REF:-}" && "$RUN_FLAG" != "$RUN_FLAG_REF" ]]; then
  echo "status=rejected(wrong/stale flag)"
  exit 10
fi
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
FLAG="$RUN_FLAG"
mkdir -p "$WORK_DIR"

# ---- 端口：优先 docker compose port 实测，回退 compose 写死的 39730/39731 ----
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8080}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  [[ "$VERSION" == "v0" ]] && PORT=39730 || PORT=39731
# 动态端口优先（compose 已转 PORT_ 动态端口）；失败回退硬编码
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && PORT="$_DYN"
export PCB_TARGET_PORT="${PORT:-}"
fi
BASE="http://127.0.0.1:${PORT}"
echo "[verify] ${VERSION} mode=${MODE} base=${BASE} flag=${FLAG}"

# ---- 就绪探测：Admidio 登录页可达（最多 120s）----
ready=0
for _ in $(seq 1 40); do
  if "$PY" - "$BASE" <<'PYEOF' 2>/dev/null; then ready=1; break; fi
import sys, urllib.request
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
import urllib.error
try:
    _op = urllib.request.build_opener(_NoRedirect)
    with _op.open(sys.argv[1] + "/system/login.php", timeout=5) as r:
        sys.exit(0)  # 任意状态码 = 应用已响应
except urllib.error.HTTPError as e:
    sys.exit(0)     # 302/4xx/5xx = 应用已响应
except Exception:
    sys.exit(1)
PYEOF
  sleep 3
done
if [[ "$ready" != 1 ]]; then echo "[verify] env not ready: ${BASE}" >&2; exit 20; fi

# ---- 幂等安装向导（Admidio 真实 install：建组织+管理员+DB schema，随后可登录）----
"$PY" - "$BASE" <<'PYEOF' || { echo "[verify] install wizard failed" >&2; exit 20; }
import sys, http.cookiejar, re, urllib.error, urllib.parse, urllib.request
BASE = sys.argv[1]
INSTALL_PATH = "/install/installation.php"
LOGIN_PATH = "/system/login.php"
ORG_SHORTNAME, ORG_LONGNAME, ORG_EMAIL = "PCB", "PCB Organization", "admin@example.com"
ADMIN_LOGIN, ADMIN_PASSWORD = "admin", "Zx9Kp2wQ7vTr!42"

def opener():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

def get(op, url, timeout=60):
    try:
        with op.open(url, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, f"<err: {e}>"

def post(op, url, fields, timeout=60):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with op.open(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, f"<err: {e}>"

def csrf(html):
    m = re.search(r'name="adm_csrf_token"[^>]*value="([^"]+)"', html)
    if not m:
        m = re.search(r'value="([^"]+)"[^>]*name="adm_csrf_token"', html)
    return m.group(1) if m else None

def login(op):
    st, html = get(op, BASE + LOGIN_PATH)
    t = csrf(html)
    if not t:
        return False
    st, body = post(op, BASE + LOGIN_PATH + "?mode=check", {
        "adm_csrf_token": t, "usr_login_name": ADMIN_LOGIN,
        "usr_password": ADMIN_PASSWORD, "org_shortname": ORG_SHORTNAME})
    return '"success"' in body

op = opener()
get(op, BASE + INSTALL_PATH + "?step=welcome")
st, html = get(op, BASE + INSTALL_PATH + "?step=create_organization")
if "adm_organization_shortname" not in html:
    print("[install] already installed")
    sys.exit(0)
t = csrf(html)
if not t:
    print("[install] no csrf", file=sys.stderr); sys.exit(1)
st, body = post(op, BASE + INSTALL_PATH + "?step=create_organization&mode=check", {
    "adm_csrf_token": t, "adm_organization_shortname": ORG_SHORTNAME,
    "adm_organization_longname": ORG_LONGNAME, "adm_organization_email": ORG_EMAIL,
    "adm_organization_timezone": "UTC"})
if '"success"' not in body and "success" not in body.lower():
    print(f"[install] org step failed: {body[:200]}", file=sys.stderr); sys.exit(1)
st, html = get(op, BASE + INSTALL_PATH + "?step=create_administrator")
t = csrf(html)
if not t:
    print("[install] no csrf on admin", file=sys.stderr); sys.exit(1)
post(op, BASE + INSTALL_PATH + "?step=create_administrator&mode=check", {
    "adm_csrf_token": t, "adm_user_last_name": "Admin", "adm_user_first_name": "PCB",
    "adm_user_email": ORG_EMAIL, "adm_user_login": ADMIN_LOGIN,
    "adm_user_password": ADMIN_PASSWORD, "adm_user_password_confirm": ADMIN_PASSWORD})
st, body = get(op, BASE + INSTALL_PATH + "?step=start_installation", timeout=300)
ok = login(opener())
print(f"[install] done installed={ok} status={st}")
sys.exit(0 if ok else 1)
PYEOF

# ---- candidate：seed 用公开 original_poc 的 URL；residual 用 rebind 域名（语义来自 held-out，不引用 hidden 文件）----
if [[ "$MODE" == "--seed" ]]; then
  URL="$("$PY" -c "import sys,json; sys.path.insert(0, '$CASE_DIR/poc'); import original_poc; print(original_poc.candidate().get('url') or '')" 2>/dev/null)"
  [[ -n "$URL" ]] || URL="https://seed.pcb.test/"
else
  URL="https://rebind.pcb.test/"
fi
"$PY" - "$URL" "$WORK_DIR/cand.json" <<'PYEOF'
import json, sys
json.dump({"url": sys.argv[1]}, open(sys.argv[2], "w"))
PYEOF

# ---- 执行公开执行器（经 runner 覆盖 BASE 端口，保持 seed_exec 逻辑不变）----
cat > "$WORK_DIR/run_probe_0023.py" <<'PYEOF'
import json, os, sys
import importlib.util
case_dir, cand_path, version, base = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
spec = importlib.util.spec_from_file_location("seed_exec",
        os.path.join(case_dir, "poc", "seed_exec.py"))
se = importlib.util.module_from_spec(spec)
spec.loader.exec_module(se)
se.BASE[version] = base
cand = json.load(open(cand_path))
r = se.run_probe(cand, version=version)
print(json.dumps(r, default=str))
PYEOF
OUT="$("$PY" "$WORK_DIR/run_probe_0023.py" "$CASE_DIR" "$WORK_DIR/cand.json" "$VERSION" "$BASE" 2>&1)" \
  || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 400; echo

# ---- 判定：fetched_body 含 RUN_FLAG_REF 即效果发生；登录失败视为环境失败 ----
printf '%s' "$OUT" > "$WORK_DIR/probe_out.json"
PCB_VERIFY_FLAG="$FLAG" "$PY" - "$WORK_DIR/probe_out.json" <<'PYEOF'
import json, os, sys
flag = os.environ["PCB_VERIFY_FLAG"]
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"[verify] probe output not json: {e}", file=sys.stderr); sys.exit(20)
if d.get("logged_in") is False:
    print("[verify] admin login failed -> env not usable", file=sys.stderr); sys.exit(20)
body = str(d.get("fetched_body") or d.get("body") or "")
sys.exit(0 if flag in body else 10)
PYEOF
rc=$?
echo "[verify] verdict rc=${rc}"
exit "$rc"
