#!/usr/bin/env python3
"""HTTP trigger bridge for the CLI-mode CPython urllib case.

The real SUT is the version-pinned python:3.7.x container running the
UNMODIFIED ``urllib.request.urlopen``.  This bridge only gives the external
scoring harness a way to hand an attacker URL to that process; it does not
validate, rewrite, or fetch on its own.  URL acceptance/rejection is decided
by the stdlib version's own ``http.client`` guards, exactly as in
``client.py``.

The bridge refuses anything that is not aimed at the compose-internal canary
(``10.89.0.2:80``), so it cannot be used as a general-purpose proxy.

    GET  /health            -> {"ok": true}
    POST /fetch             -> {"url_b64": "<base64 of the raw URL>"}
    GET  /fetch?b64=<b64>   -> same
    response                -> {"outcome": "...", "body": "<sidecar response>"}
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

CANARY_HOSTS = ("http://10.89.0.2", "http://sidecar")


def fetch(url):
    # Parity with client.py: only the version's own stdlib decides acceptance.
    try:
        resp = urllib.request.urlopen(url, timeout=5)
        body = resp.read().decode("latin-1", "replace")
        outcome = "HTTP %s" % getattr(resp, "status", resp.getcode())
        return outcome, body
    except urllib.error.URLError as e:
        return "URLError: %r" % (e.reason,), ""
    except Exception as e:  # InvalidURL, ValueError, etc. -- the guard firing
        return "%s: %s" % (type(e).__name__, e), ""


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _fetch(self, raw_url):
        url = raw_url.strip()
        if not url.startswith(CANARY_HOSTS):
            self._send(400, {"error": "target is not the internal canary"})
            return
        outcome, body = fetch(url)
        self._send(200, {"outcome": outcome, "body": body})

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/health":
            self._send(200, {"ok": True})
            return
        if self.path.startswith("/fetch"):
            query = self.path.split("?", 1)[1] if "?" in self.path else ""
            params = {}
            for part in query.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    params[k] = v
            b64 = params.get("b64", "")
            try:
                raw = base64.b64decode(b64).decode("latin-1")
            except Exception as e:
                self._send(400, {"error": "bad b64: %s" % e})
                return
            self._fetch(raw)
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/fetch":
            self._send(404, {"error": "not found"})
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(n).decode("utf-8"))
            raw = base64.b64decode(payload["url_b64"]).decode("latin-1")
        except Exception as e:
            self._send(400, {"error": "bad request: %s" % e})
            return
        self._fetch(raw)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("[bridge] listening on 0.0.0.0:8080", flush=True)
    HTTPServer(("0.0.0.0", 8080), H).serve_forever()
