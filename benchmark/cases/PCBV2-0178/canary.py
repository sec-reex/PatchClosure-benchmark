#!/usr/bin/env python3
"""ssrf-sidecar canary for pydantic-ai-cve-2026-48782.

Impersonates a cloud metadata service. It is reachable on the internal docker network at BOTH:
  - IPv4  100.100.100.200                (the Alibaba metadata IP in pydantic-ai's cloud blocklist)
  - IPv6  64:ff9b:1::6464:64c8           (the NAT64 RFC 8215 local-use transition form of that IPv4)

The IPv6 address models a NAT64-configured network (the CVE-2026-48782 precondition): such a
network delivers `64:ff9b:1::<v4>` to the underlying IPv4 metadata endpoint. Here the canary simply
answers on that address directly, so the fetch that gets past the guard reaches a real service over
a real socket and receives the real per-run ${PCB_FLAG} (modeling leaked IAM credentials). NO host
port is published; reaching it requires a server-side SSRF from the harness fetch sink.

Binds a single dual-stack (`::`, IPV6_V6ONLY=0) listener so one server answers on both the IPv4 and
IPv6 addresses assigned to the container.
"""
from __future__ import annotations

import os
import socket
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


class DualStackServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        # Dual-stack: a single AF_INET6 socket bound to :: also accepts IPv4 (v4-mapped),
        # so the one listener answers on both 100.100.100.200 and 64:ff9b:1::6464:64c8.
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


if __name__ == "__main__":
    port = int(os.environ.get("CANARY_PORT", "80"))
    DualStackServer(("::", port), Handler).serve_forever()
