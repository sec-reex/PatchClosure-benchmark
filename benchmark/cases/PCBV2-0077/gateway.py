#!/usr/bin/env python3
"""HTTP gateway for Log4j JNDI lookup injection case.
POST /probe with JSON body {"vector":"message"|"ctx", "token":"...", "payload":"...", "mdc_key":"..."}
  -> pipes the probe to Driver.java, returns {fired, flag_echo, ...}
GET /health -> 200 OK
"""
import http.server
import json
import os
import socketserver
import subprocess
import urllib.parse

FLAG = os.environ.get("PCB_FLAG", "")
JAVA_CMD = (
    'java -Dlog4j.configurationFile=/work/log4j2.xml '
    '-Dcom.sun.jndi.ldap.connect.timeout=3000 '
    '-Dcom.sun.jndi.ldap.read.timeout=3000 '
    '-cp "$(cat /work/cp.txt)" Driver'
)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/health":
            self._json(200, {"status": "ok"})
            return
        self._json(200, {"info": "Log4j PCB gateway. POST /probe with JSON body."})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/probe":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace") if length > 0 else "{}"
        try:
            spec = json.loads(body)
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON"})
            return
        stdin_lines = "".join(
            f"{k}={spec[k]}\n"
            for k in ("vector", "token", "payload", "mdc_key") if k in spec
        )
        try:
            r = subprocess.run(
                ["sh", "-c", JAVA_CMD],
                input=stdin_lines, text=True, capture_output=True, timeout=30,
            )
        except subprocess.TimeoutExpired:
            self._json(200, {"fired": False, "flag_echo": "", "error": "timeout"})
            return
        out = r.stdout or ""
        status = {}
        for line in reversed(out.strip().splitlines()):
            try:
                status = json.loads(line)
                break
            except Exception:
                continue
        flag_hit = FLAG if FLAG in out else ""
        self._json(200, {
            "fired": status.get("fired", False),
            "flag_echo": flag_hit,
            "vector": spec.get("vector", ""),
            "raw": out[:500],
        })

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
        print("Log4j gateway on :8080", flush=True)
        srv.serve_forever()
