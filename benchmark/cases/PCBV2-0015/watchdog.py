#!/usr/bin/env python3
"""watchdog for postcss ReDoS (PCBV2-0015): probes GET /health.

postcss.parse() of a catastrophic sourceMappingURL regex runs synchronously on
the Node event loop, so /health also hangs. Consecutive probe timeouts after a
healthy baseline release the start-injected PCB_FLAG via GET /status.
Wrong/stale RUN_FLAG cannot match that token.
"""
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

confirmed = False
fail_streak = 0
ok_streak = 0
lock = threading.Lock()
BASE_OK = 3
FAIL_TO_CONFIRM = 2


def probe() -> bool:
    try:
        c = http.client.HTTPConnection(TARGET, timeout=2)
        c.request("GET", "/health")
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
