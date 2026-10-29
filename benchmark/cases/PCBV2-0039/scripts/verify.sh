#!/usr/bin/env bash
# verify.sh --seed|--residual — PCBV2-0039 froxlor-cve-2026-41234 定制验证
# 0=效果发生(RUN_FLAG 出现在效果通道) 10=未发生 20=环境失败 30=参数错误
#
# case 机制（BIND zone newline injection, CVE-2026-30932 -> CVE-2026-41234）：
#   DomainZones.add 把 content 原样存入 panel_domains_dns；DNS rebuild cron 把
#   `record TTL IN TYPE content\n` 写入 /etc/bind/domains/pcb.local.zone，
#   content 内的换行可跳出记录行注入任意 BIND 行（这里注入注释行 `; pcb_<FLAG>`）。
#   seed    = RP 记录 newline 注入（CVE-2026-30932）：v0 生效；v1 validateDnsRp 406 阻断
#   residual= TXT 记录 newline 注入（CVE-2026-41234，修复遗漏 TXT）：v1 引号内断行仍生效；
#             v2 剥离控制字符后阻断
# 效果通道 = zone 文件中的注释行（poc_common.probe 的 body 只含 `;` 开头的行）。
# 注入内容里的 flag 从容器 canary(/canary.txt, start.sh 注入的 PCB_FLAG) 读取，
# 因此平台用 wrong/stale RUN_FLAG 重跑时匹配失败 -> 非 0（fresh-flag 通道）。
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
case "$VERSION" in v0|v1|v2) ;; *) echo "bad VERSION=$VERSION" >&2; exit 30 ;; esac

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR" 2>/dev/null || true
if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
CONTAINER="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" ps -q "$VERSION" 2>/dev/null | head -1)"
if [[ -z "$CONTAINER" ]]; then
  echo "container for $VERSION not running (need --profile)" >&2
  exit 20
fi

# 应用侧真实 flag（start.sh 注入 -> entrypoint 写入 canary）
# entrypoint 异步写入 canary：轮询等待（最多 180s）
APP_FLAG=""
for _ in $(seq 1 90); do
  APP_FLAG="$(docker exec "$CONTAINER" cat /canary.txt 2>/dev/null | tr -d '\r\n[:space:]')" || APP_FLAG=""
  [[ -n "$APP_FLAG" ]] && break
  sleep 2
done
if [[ -z "$APP_FLAG" ]]; then
  echo "cannot read canary flag from $CONTAINER" >&2
  exit 20
fi

PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$VERSION" 80 2>/dev/null | awk -F: 'NR==1{gsub(/[[:space:]]/,"",$NF); print $NF}')"
if [[ -z "$PORT" ]]; then
  case "$VERSION" in
    v0) PORT="${PORT_V0_0:-}" ;;
    v1) PORT="${PORT_V1_0:-}" ;;
    v2) PORT="${PORT_V2_0:-}" ;;
  esac
fi
[[ -n "$PORT" ]] || { echo "verify: 无法解析 $VERSION 宿主端口（need --profile + compose.env）" >&2; exit 20; }
export PCB_TARGET_PORT="$PORT" PCB_APP_PORT="$PORT" PCB_CONTAINER="$CONTAINER"

MODE_TYPE="RP"; MODE_CONTENT="mbox.example.com. txt.example.com."
if [[ "$MODE" == "--residual" ]]; then MODE_TYPE="TXT"; MODE_CONTENT="hello"; fi

# 执行 case 真实逻辑（poc_common.probe: API 添加 -> 真实 DNS rebuild cron -> 读 zone 注释行）
OUT="$("$PY" - "$VERSION" "$MODE_TYPE" "$MODE_CONTENT" "$APP_FLAG" "$CASE_DIR" <<'PYEOF'
import sys, json, importlib.util
version, rtype, rcontent, app_flag, case_dir = sys.argv[1:6]
spec = importlib.util.spec_from_file_location('poc_common', case_dir + '/poc_common.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
try:
    res = mod.probe(version, rtype, "%s\n; pcb_%s" % (rcontent, app_flag), app_flag)
except Exception as e:
    print(json.dumps({'ok': False, 'status': 0, 'body': '', 'error': str(e)[:200]}))
else:
    print(json.dumps(res, default=str))
PYEOF
)" || { echo "probe failed: $OUT" >&2; exit 20; }
{ printf '%s' "$OUT" > "$WORK_DIR/verify_result.json"; } 2>/dev/null || true

# 摘要（效果通道本身，可打印）
printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print('mode=%s api_status=%s zone_len=%s' % ('$MODE', d.get('status'), d.get('zone_len')))
    print((d.get('body') or '(no comment lines)')[:500])
except Exception as e:
    print('bad probe output: %s' % e)"

ST="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try: print(json.load(sys.stdin).get('status', 0))
except Exception: print(0)" 2>/dev/null || echo 0)"
if [[ "$ST" == "0" ]]; then echo "API unreachable (status=0)" >&2; exit 20; fi

# flag 判定：RUN_FLAG 必须出现在效果通道（zone 注释行）
if grep -qF "$RUN_FLAG" <<<"$OUT"; then
  echo "RESULT: effect observed (flag present in zone comments)"
  exit 0
else
  echo "RESULT: effect blocked (flag absent from zone comments)"
  exit 10
fi
