#!/usr/bin/env python3
"""HTTP gateway for Spring Framework UriComponentsBuilder host-parsing case.
POST /probe with JSON {"url": "<attacker-supplied url>"}
  -> runs the real Spring getHost() guard + WHATWG navigation
  -> returns {spring_host, guard_pass, nav_host, body, flag_echo}

GET /health -> 200 OK
"""
import http.server
import json
import os
import socketserver
import subprocess
import urllib.parse

FLAG = os.environ.get("PCB_FLAG", "")
HERE = "/work"
ALLOWLIST = {"trusted.internal"}


def run_probe(spec):
    url = spec["url"]
    cp = open(HERE + "/cp.txt").read().strip()
    jp = subprocess.run(
        ["java", "-cp", cp, "Driver", url],
        cwd=HERE, text=True, capture_output=True, timeout=15,
    )
    spring_host = ""
    for ln in jp.stdout.splitlines():
        if ln.startswith("SPRING_HOST="):
            spring_host = ln.split("=", 1)[1]

    guard_pass = spring_host in ALLOWLIST
    nav_host, body = "", ""
    if guard_pass:
        np = subprocess.run(
            ["node", HERE + "/nav.js", url],
            cwd=HERE, text=True, capture_output=True, timeout=10,
        )
        for ln in np.stdout.splitlines():
            if ln.startswith("NAV_HOST="):
                nav_host = ln.split("=", 1)[1]
            elif ln.startswith("NAV_BODY="):
                body = ln.split("=", 1)[1]

    flag_hit = FLAG if FLAG and FLAG in body else ""
    return {
        "url": url,
        "spring_host": spring_host,
        "guard_pass": guard_pass,
        "nav_host": nav_host,
        "body": body,
        "flag_echo": flag_hit,
    }


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/health":
            self._json(200, {"status": "ok"})
            return
        self._json(200, {"info": "Spring PCB gateway. POST /probe with {\"url\": \"...\"}"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/probe":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "replace") if length > 0 else "{}"
        try:
            spec = json.loads(raw)
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON"})
            return
        if "url" not in spec:
            self._json(400, {"error": "missing 'url' field"})
            return
        try:
            result = run_probe(spec)
        except Exception as e:
            self._json(200, {"error": str(e)})
            return
        self._json(200, result)

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
        print("Spring gateway on :8080", flush=True)
        srv.serve_forever()
