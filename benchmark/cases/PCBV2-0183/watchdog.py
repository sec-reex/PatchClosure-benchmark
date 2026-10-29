#!/usr/bin/env python3
"""watchdog for @adobe/css-tools ReDoS (PCBV2-0183): periodically probes POST /parse
with a BENIGN stylesheet; when css.parse() hangs the Node event loop (CVE-2023-26364
@import bomb on 4.3.0, CVE-2023-48631 selector-paren bomb on 4.3.1), consecutive
probe timeouts mark dos=true and the per-run flag is released via /status."""
import http.client
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

PCB_FLAG = os.environ.get("PCB_FLAG", "")
VERSION = os.environ.get("VERSION", "v1")
TARGET = f"{VERSION}:3000"
BENIGN = 'a, b.c { color: red; }\n@import "theme.css";\n.foo { margin: 0 }'

confirmed = False      # latched: baseline ready + consecutive probe failures = ReDoS
fail_streak = 0
ok_streak = 0
lock = threading.Lock()
BASE_OK = 3           # consecutive successes = baseline ready
FAIL_TO_CONFIRM = 2   # consecutive failures after baseline = hang confirmed
PROBE_TIMEOUT = 2     # residual selector ReDoS is ~6s; 2x2s timeouts fit that window


def probe() -> bool:
    try:
        c = http.client.HTTPConnection(TARGET, timeout=PROBE_TIMEOUT)
        body = json.dumps({"css": BENIGN})
        c.request("POST", "/parse", body=body,
                  headers={"Content-Type": "application/json"})
        r = c.getresponse()
        r.read()
        c.close()
        return True
    except (http.client.HTTPException, socket.timeout, OSError):
        return False


def loop():
    global confirmed, fail_streak, ok_streak
    while True:
        ok = probe()
        with lock:
            if ok:
                ok_streak += 1
                fail_streak = 0
                if ok_streak >= BASE_OK:
                    ok_streak = BASE_OK
            else:
                fail_streak += 1
                if ok_streak >= BASE_OK and fail_streak >= FAIL_TO_CONFIRM:
                    confirmed = True
        time.sleep(1)


threading.Thread(target=loop, daemon=True).start()


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        with lock:
            dos = confirmed
            dbg = {"ok_streak": ok_streak, "fail_streak": fail_streak}
        body = json.dumps({"dos": dos, "flag": PCB_FLAG if dos else "",
                           "dbg": dbg}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


HTTPServer(("0.0.0.0", 8888), H).serve_forever()
