#!/usr/bin/env python3
"""Internal-only exfil callback for the xss-exfil canary (TestLink reqURI reflected XSS).

Records every GET /c?f=<...> it receives (the XSS payload navigates the iframe here carrying the
victim's document.cookie, which contains ${PCB_FLAG}). Success = the flag substring appears in a
hit. /dump returns recorded hits (read by the host-side oracle); /reset clears between probes.
The victim's browser reaches it internally as http://callback:9000/ ; /dump is published on a host
port only so the oracle can read the result. The flag only ever arrives here via JS EXECUTION.
"""
import http.server
import socketserver
import urllib.parse
import json

_hits = []


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        if q.path == "/c":
            _hits.append(self.path)  # full path incl ?f=session=<flag>
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
        elif q.path == "/dump":
            body = json.dumps(_hits).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        elif q.path == "/reset":
            _hits.clear()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"reset")
        elif q.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    Server(("0.0.0.0", 9000), H).serve_forever()
