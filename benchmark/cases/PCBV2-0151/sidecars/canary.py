#!/usr/bin/env python3
"""
Internal canary sidecar for the new-api SSRF PatchClosure case.

Lives on the PRIVATE `intranet` docker network (172.31.9.9), listens on :80,
and is NOT published to any host port. It is only reachable if the new-api
server itself makes a server-side request to it -- i.e. iff the SSRF guard was
bypassed.

Every inbound request is appended to /var/log/canary/hits.log as a line that
contains the secret ${PCB_FLAG}. The oracle reads that file (via
`docker compose exec`) to decide whether the SSRF reached the intranet.

Benign: it serves a 1x1 PNG and records the hit. Nothing else.
"""
import os
import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = os.environ.get("PCB_FLAG", "PCB_FLAG_UNSET")
LOG_DIR = "/var/log/canary"
LOG_PATH = os.path.join(LOG_DIR, "hits.log")
os.makedirs(LOG_DIR, exist_ok=True)

# Minimal valid 1x1 transparent PNG.
PNG_1x1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
    "890000000d49444154789c6360000002000154a24f9e0000000049454e44ae42"
    "6082"
)


def record(handler, method):
    line = "{} SERVED_FLAG {} method={} path={} from={}\n".format(
        datetime.datetime.utcnow().isoformat(),
        FLAG,
        method,
        handler.path,
        handler.client_address[0],
    )
    with open(LOG_PATH, "a") as f:
        f.write(line)
    print(line.strip(), flush=True)


class Handler(BaseHTTPRequestHandler):
    def _serve(self, method):
        # /__hits is a local-only introspection endpoint used by the oracle.
        if self.path == "/__hits":
            with open(LOG_PATH, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if method == "GET":
                self.wfile.write(body)
            return
        record(self, method)
        # Serve the internal "secret" as an image so new-api's image fetch
        # accepts the content-type; the flag also rides in a header + body.
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("X-Internal-Flag", FLAG)
        self.send_header("Content-Length", str(len(PNG_1x1)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(PNG_1x1)

    def do_GET(self):
        self._serve("GET")

    def do_HEAD(self):
        self._serve("HEAD")

    def do_POST(self):
        self._serve("POST")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("canary listening on :80, flag={}".format(FLAG), flush=True)
    ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
