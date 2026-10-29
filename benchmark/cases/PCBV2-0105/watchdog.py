#!/usr/bin/env python3
"""watchdog for Rack::Files byte-range DoS (PCBV2-0105): probes GET /health.

Hang signal (per case contract): HTTP timeout / crash OR probe latency > 1s
(T_SLOW). When WEBrick is occupied assembling a huge multipart/byteranges body
(or the 512m container is OOM-killed), consecutive slow/failed probes mark
dos=true and the per-run PCB_FLAG is released via /status. GET /trip latches
the same release from verify.sh's own crash/timeout / latency>1s measurement.
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
FAIL_TO_CONFIRM = 1  # a single >2s / timeout probe after baseline = hang
HANG_S = 2.0
PROBE_TIMEOUT_S = 10.0


def probe() -> bool:
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection(TARGET, timeout=PROBE_TIMEOUT_S)
        c.request("GET", "/health")
        r = c.getresponse()
        r.read()
        c.close()
        return (time.perf_counter() - t0) <= HANG_S
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
        global confirmed
        path = self.path.split("?", 1)[0]
        with lock:
            if path == "/trip":
                confirmed = True
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
