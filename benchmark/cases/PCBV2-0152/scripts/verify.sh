#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# nextjs-cve-2026-45109：seed 与 residual 是同一请求（GET /admin.rsc, RSC:1）；
# 区别只在构建管线 —— seed 指向 webpack 服务（v0 / v1_web），residual 指向 Turbopack 服务（v1_turbo）。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
# Leftover seed state can make a second /admin.rsc probe look like a
# connection failure (exit 20). wrong/stale must reject without re-probing.
if [[ -n "${RUN_FLAG_REF:-}" && "$RUN_FLAG" != "$RUN_FLAG_REF" ]]; then
  echo "status=rejected(wrong/stale flag)"
  exit 10
fi
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
# 服务发现：版本段出现在名字任意位置（v1_web/v1_turbo 这类前缀式命名）。
#   seed     -> 排除 turbo 的版本服务（v0 或 v1_web；webpack 管线）
#   residual -> 选 turbo 的版本服务（v1_turbo；Turbopack 管线，CVE-2026-45109 未覆盖）
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|[-_])$VERSION([-_]|$)")"
if [[ "$MODE" == "--seed" ]]; then
  SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "turbo|db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
else
  SVC="$(printf '%s\n' "$_SVC_ALL" | grep -E "turbo" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
fi
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-3000}"
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
export PCB_TARGET_PORT="${PORT:-}"
if [[ -z "$PORT" ]]; then
  echo "verify: 无法解析端口 SVC=$SVC CPORT=$CPORT" >&2
  exit 20
fi
# seed 与 residual 共用同一 candidate（transport-variant 请求）
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
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -q "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
