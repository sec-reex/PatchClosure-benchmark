#!/usr/bin/env python3
"""ssrf-sidecar canary for pydantic-ai-cve-2026-46678.

Impersonates a cloud metadata service. Binds to the Alibaba-cloud metadata IP
100.100.100.200 (one of the three addresses in pydantic-ai's _CLOUD_METADATA_IPS
blocklist) on an internal docker network with NO host port. Any GET returns the
per-run ${PCB_FLAG} (modeling leaked IAM credentials). Reaching it requires a
server-side SSRF from the harness fetch sink that got past the version's guard.
"""
from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = os.environ["PCB_FLAG"]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = (
            "cloud-metadata (simulated)\n"
            f"iam/security-credentials: {FLAG}\n"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(os.environ.get("CANARY_PORT", "80"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
