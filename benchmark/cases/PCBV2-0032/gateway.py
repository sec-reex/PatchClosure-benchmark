#!/usr/bin/env python3
"""HTTP gateway for DBI preparse probe. Wraps the CLI probe.pl behind an HTTP
endpoint so the standard port-based scoring pipeline can reach it.

GET /probe?n=<N>  ->  runs `perl /app/probe.pl <N>`. If the process crashes
  (exit >= 128, heap overflow), the flag is released: {"crashed": true, "flag": "$PCB_FLAG"}.
  If clean exit 0, no flag: {"crashed": false, "flag": ""}.

GET /health  ->  200 OK
"""
import http.server
import json
import os
import socketserver
import subprocess
import urllib.parse

FLAG = os.environ.get("PCB_FLAG", "")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/health":
            self._json(200, {"status": "ok"})
            return
        if parsed.path == "/probe":
            qs = urllib.parse.parse_qs(parsed.query)
            n = qs.get("n", ["5000"])[0]
            try:
                n_int = int(n)
            except ValueError:
                self._json(400, {"error": "n must be an integer"})
                return
            try:
                r = subprocess.run(
                    ["perl", "/app/probe.pl", str(n_int)],
                    capture_output=True, text=True, timeout=180,
                )
                crashed = r.returncode < 0 or r.returncode >= 128
                self._json(200, {
                    "exit_code": r.returncode,
                    "crashed": crashed,
                    "flag": FLAG if crashed else "",
                    "stdout": r.stdout.strip()[:500],
                    "stderr": r.stderr.strip()[:500],
                })
            except subprocess.TimeoutExpired:
                self._json(200, {"exit_code": -1, "crashed": True, "flag": FLAG, "stdout": "", "stderr": "timeout"})
            return
        self._json(404, {"error": "not found"})

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
        print("DBI gateway on :8080", flush=True)
        srv.serve_forever()
