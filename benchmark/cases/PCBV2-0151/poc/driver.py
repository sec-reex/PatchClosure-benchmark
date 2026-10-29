#!/usr/bin/env python3
"""Drive official new-api over its own HTTP API.

setup: POST /api/setup + login + channel + token
fire:  POST /v1/chat/completions with a user-supplied image_url
       (the real GET_MEDIA_TOKEN download sink — not a ValidateURL harness)
"""
import json
import sys
import time
import urllib.error
import urllib.request

ADMIN_USER = "root"
ADMIN_PASS = "rootpass123"


def http_json(method, url, data=None, headers=None, cookie=None, timeout=45):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        raw = resp.read().decode("utf-8", "replace")
        set_cookie = resp.headers.get("Set-Cookie")
        try:
            return resp.status, json.loads(raw), set_cookie
        except Exception:
            return resp.status, raw, set_cookie
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw), None
        except Exception:
            return e.code, raw, None
    except Exception as e:
        return 0, str(e), None


def wait_ready(base, timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st, body, _ = http_json("GET", base + "/api/status", timeout=8)
        if st == 200 and isinstance(body, dict) and body.get("success"):
            return True
        time.sleep(2)
    return False


def ensure_setup(base):
    st, body, _ = http_json("GET", base + "/api/setup")
    if isinstance(body, dict) and body.get("data", {}).get("status"):
        return True
    st, body, _ = http_json("POST", base + "/api/setup", {
        "username": ADMIN_USER,
        "password": ADMIN_PASS,
        "confirmPassword": ADMIN_PASS,
        "SelfUseModeEnabled": True,
        "DemoSiteEnabled": False,
    })
    msg = body if isinstance(body, str) else (body or {}).get("message")
    print("[*] setup -> %s %s" % (st, msg), file=sys.stderr)
    if st == 200 and isinstance(body, dict) and body.get("success"):
        return True
    # already initialized is also fine
    if isinstance(body, dict) and body.get("data", {}).get("status"):
        return True
    st2, body2, _ = http_json("GET", base + "/api/setup")
    return isinstance(body2, dict) and body2.get("data", {}).get("status")


def setup_relay(base):
    if not ensure_setup(base):
        print("[!] setup failed", file=sys.stderr)
        return None
    st, body, cookie = http_json(
        "POST", base + "/api/user/login",
        {"username": ADMIN_USER, "password": ADMIN_PASS})
    if st != 200 or not isinstance(body, dict) or not body.get("success"):
        print("[!] login failed: %s %s" % (st, body), file=sys.stderr)
        return None
    uid = body["data"]["id"]
    hdr = {"New-Api-User": str(uid)}
    cke = cookie.split(";")[0] if cookie else None
    print("[+] logged in as root uid=%s" % uid, file=sys.stderr)

    ch = {
        "mode": "single",
        "channel": {
            "name": "pcb-dummy",
            "type": 1,
            "key": "sk-pcb-dummy",
            "base_url": "http://11.11.11.10:8080",
            "models": "gpt-4o",
            "group": "default",
            "groups": ["default"],
            "model_mapping": "",
            "status": 1,
        },
    }
    st, body, _ = http_json("POST", base + "/api/channel/", ch, hdr, cke)
    msg = body if isinstance(body, str) else (body or {}).get("message")
    print("[*] create channel -> %s %s" % (st, msg), file=sys.stderr)

    tk = {
        "name": "pcb-token",
        "expired_time": -1,
        "unlimited_quota": True,
        "remain_quota": 500000,
        "model_limits_enabled": False,
        "group": "default",
    }
    st, body, _ = http_json("POST", base + "/api/token/", tk, hdr, cke)
    msg = body if isinstance(body, str) else (body or {}).get("message")
    print("[*] create token -> %s %s" % (st, msg), file=sys.stderr)

    st, body, _ = http_json("GET", base + "/api/token/?p=0&size=10", None, hdr, cke)
    if not (isinstance(body, dict) and body.get("success")):
        print("[!] list tokens failed: %s %s" % (st, body), file=sys.stderr)
        return None
    items = body["data"]
    if isinstance(items, dict):
        items = items.get("items") or items.get("records") or items.get("data") or []
    if not items:
        print("[!] no tokens found", file=sys.stderr)
        return None
    key = items[0].get("key") or ""
    if not key:
        print("[!] empty token key", file=sys.stderr)
        return None
    if not key.startswith("sk-"):
        key = "sk-" + key
    print("[+] token key acquired", file=sys.stderr)
    return key


def fire(base, sk, image_url):
    payload = {
        "model": "gpt-4o",
        "stream": False,
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "describe"},
                {"type": "image_url",
                 "image_url": {"url": image_url, "detail": "high"}},
            ],
        }],
    }
    st, body, _ = http_json(
        "POST", base + "/v1/chat/completions", payload,
        {"Authorization": "Bearer " + sk},
        timeout=60)
    snippet = body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)
    print("[*] relay resp %s: %s" % (st, snippet[:400]), file=sys.stderr)
    return st, snippet


def main():
    if len(sys.argv) < 3:
        print("usage: driver.py wait|setup|fire|run BASE [IMAGE_URL]", file=sys.stderr)
        return 30
    cmd, base = sys.argv[1], sys.argv[2].rstrip("/")
    if cmd == "wait":
        return 0 if wait_ready(base) else 20
    if cmd == "setup":
        if not wait_ready(base, timeout=30):
            return 20
        return 0 if setup_relay(base) else 20
    if cmd in ("fire", "run"):
        if len(sys.argv) < 4:
            print("usage: driver.py fire|run BASE IMAGE_URL", file=sys.stderr)
            return 30
        url = sys.argv[3]
        if not wait_ready(base, timeout=30):
            return 20
        sk = setup_relay(base)
        if not sk:
            return 20
        st, _ = fire(base, sk, url)
        # 0 = transport/setup failed; app 4xx/5xx (blocked / dummy upstream) is OK
        return 20 if st == 0 else 0
    print("unknown cmd: %s" % cmd, file=sys.stderr)
    return 30


if __name__ == "__main__":
    sys.exit(main())
