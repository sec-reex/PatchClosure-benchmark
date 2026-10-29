#!/usr/bin/env python3
"""Sidecar for the n8n benchmark case.

Records every GET /ingest?f=<token> hit (the workflow exfil channel) and
serves /flag (planted canary value for OOB-style checks). Internal-only.
"""
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

FLAG = os.environ.get("PCB_FLAG", "PCBFLAG_UNSET")
HITS = []
LOCK = threading.Lock()
HITS_FILE = "/sidecar_hits.json"


def persist():
    try:
        with open(HITS_FILE, "w") as f:
            f.write("\n".join(HITS))
    except Exception:
        pass


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/health"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path.startswith("/flag"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(FLAG.encode())
            return
        if self.path.startswith("/clear"):
            with LOCK:
                HITS.clear()
                persist()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"cleared")
            return
        with LOCK:
            HITS.append(f"[{time.strftime('%H:%M:%S')}] {self.path}")
            persist()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"recorded")
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length)
        with LOCK:
            HITS.append(f"[{time.strftime('%H:%M:%S')}] {self.path}|{body.decode('utf-8', 'replace')[:2000]}")
            persist()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"recorded")


HTTPServer(("0.0.0.0", 8000), H).serve_forever()
