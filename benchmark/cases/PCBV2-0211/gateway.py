#!/usr/bin/env python3
"""HTTP gateway for urllib3 cross-origin redirect header-strip case.
GET /probe?mode=seed     -> runs seed probe (Cookie header)
GET /probe?mode=residual -> runs residual probe (Proxy-Authorization header)
Returns the attacker collector's echo of received headers as JSON.
Flag leaks if the sensitive header was NOT stripped on cross-origin redirect.
"""
import http.server
import json
import os
import socketserver
import urllib.parse

import urllib3

FLAG = os.environ.get("PCB_FLAG", "NO_FLAG")


def run_probe(mode):
    if mode == "seed":
        headers = {"Cookie": "session=" + FLAG}
    else:
        headers = {"Proxy-Authorization": "Basic " + FLAG}

    pool = urllib3.PoolManager()
    try:
        resp = pool.request("GET", "http://redirector/redir", headers=headers, redirect=True)
        body = resp.data.decode("utf-8", "replace")
        return {"status": resp.status, "headers": body, "flag_leaked": FLAG in body}
    except Exception as e:
        return {"error": str(e)}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/health":
            self._json(200, {"status": "ok"})
            return
        if parsed.path == "/probe":
            qs = urllib.parse.parse_qs(parsed.query)
            mode = qs.get("mode", ["residual"])[0]
            result = run_probe(mode)
            self._json(200, result)
            return
        self._json(200, {"info": "urllib3 PCB gateway. Use /probe?mode=seed or /probe?mode=residual"})

    def _json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", 8080), Handler) as srv:
        print("urllib3 gateway on :8080", flush=True)
        srv.serve_forever()
