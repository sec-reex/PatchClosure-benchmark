#!/usr/bin/env python3
"""Faithful-core harness for the CPython stdlib http.client CRLF-injection guard
(CVE-2019-9740 -> CVE-2019-18348).

Standing up a whole web app just to drive ONE guarded request-serialization is
disproportionate, so this image runs the REAL, per-version CPython stdlib
`http.client` as the guard in front of a real socket -- exactly the boundary both
CVEs concern. No offensive PoC is used; the target is a benign per-run ${PCB_FLAG}
served by an internal line-based listener (a stand-in for the internal line-based
services -- Redis/memcached -- that CVE-2019-18348 host-CRLF injection targets).

  HARNESS_VER=v0  python 3.7.3  -- pre-fix: neither `_validate_path` nor
                  `_validate_host`. A CRLF in the request path (CVE-2019-9740) and
                  a CRLF in the host both reach the wire.                 [seed env]
  HARNESS_VER=v1  python 3.7.7  -- the CVE-2019-9740 fix: `putrequest` calls
                  `_validate_path(url)` (regex `_contains_disallowed_url_pchar_re`
                  = [\\x00-\\x20\\x7f]) so a path CRLF is rejected (seed BLOCKED).
                  INCOMPLETE: the *host* component is NOT validated, so a CRLF in
                  the host still reaches the wire -> CVE-2019-18348.  [TARGET, GIVEN]
  HARNESS_VER=v2  python 3.7.8  -- the CVE-2019-18348 fix: HTTPConnection.__init__
                  calls `_validate_host(self.host)` with the same regex, so a CRLF
                  host is rejected at construction (residual BLOCKED).      [negative]

Route: GET /probe?host=<b64>&path=<b64>. The harness constructs the version's real
`http.client.HTTPConnection(host)` and calls `request("GET", path)`; connect() is
overridden to force the socket to the internal 127.0.0.1 flag listener (address
resolution is orthogonal to the request-serialization sink both CVE fixes guard --
this is the Netty NoopAddressResolver technique). Whether the CRLF survives to the
wire is decided ENTIRELY by that version's unmodified stdlib. The internal listener
returns ${PCB_FLAG} iff it observes an injected inline `GET flag` line -- proof the
CRLF split fired past the version's guard. Nothing in CPython is modified.
"""
import base64
import http.client as hc
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

VER = os.environ.get("HARNESS_VER", "v1")
APP_PORT = int(os.environ.get("APP_PORT", "8080"))
FLAG_PORT = int(os.environ.get("FLAG_PORT", "9000"))
FLAG = os.environ.get("PCB_FLAG", "PCB_FLAG_unset")

import platform
PYVER = platform.python_version()


# ---- internal canary: loopback-only line-based flag service (no host port) -----------------
def _flag_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", FLAG_PORT))
    s.listen(16)
    while True:
        try:
            c, _ = s.accept()
        except OSError:
            continue
        threading.Thread(target=_flag_handle, args=(c,), daemon=True).start()


def _flag_handle(c):
    """Benign line-based internal service: returns ${PCB_FLAG} iff it sees an inline
    `GET flag` command line (leading whitespace tolerated, as Redis-style inline
    parsing does) -- i.e. iff a CRLF injection smuggled that line onto the wire."""
    c.settimeout(1.5)
    data = b""
    try:
        while b"\r\n\r\n" not in data and len(data) < 16384:
            chunk = c.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    served = False
    for raw in data.split(b"\n"):
        toks = raw.replace(b"\r", b" ").split()  # inline parse; leading whitespace tolerated
        if len(toks) >= 2 and toks[0].upper() == b"GET" and toks[1] == b"flag":
            served = True
    body = (FLAG if served else "NO-FLAG").encode()
    try:
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                  % (len(body), body))
    except OSError:
        pass
    try:
        c.close()
    except OSError:
        pass


# ---- the request-serialization sink under test: the version's real http.client -------------
class _Conn(hc.HTTPConnection):
    def connect(self):
        # Force the socket to the internal flag listener. Host resolution is orthogonal to the
        # request-building sink the CVE fixes guard; this isolates that sink faithfully.
        self.sock = socket.create_connection(("127.0.0.1", FLAG_PORT), timeout=4)


def _drive(host, path):
    """Run the version's real http.client with attacker-influenced host/path.
    Returns (stage, flag_echo). stage is 'sent' | 'construct-blocked:*' | 'request-blocked:*'.
    flag_echo is ${PCB_FLAG} iff the internal listener served it (injection reached the wire)."""
    try:
        conn = _Conn(host, 80, timeout=4)         # <-- V2's _validate_host fires HERE
    except Exception as e:  # noqa: BLE001
        return ("construct-blocked:%s:%s" % (type(e).__name__, str(e)[:80]), "")
    try:
        conn.request("GET", path)                 # <-- V1's _validate_path fires HERE (for the path seed)
        resp = conn.getresponse()
        body = resp.read().decode("latin-1")
    except Exception as e:  # noqa: BLE001
        return ("request-blocked:%s:%s" % (type(e).__name__, str(e)[:80]), "")
    return ("sent", FLAG if FLAG in body else "")


# ---- control server (host-published) -------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _b64(self, qs, key, default=""):
        v = qs.get(key, [None])[0]
        if v is None:
            return default
        return base64.urlsafe_b64decode(v.encode()).decode("latin-1")

    def do_GET(self):
        u = urlparse(self.path)
        if u.path != "/probe":
            out = ("python-http.client faithful-core harness %s (python %s) ok" % (VER, PYVER)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
            return
        qs = parse_qs(u.query)
        host = self._b64(qs, "host", "127.0.0.1")
        path = self._b64(qs, "path", "/")
        stage, flag_echo = _drive(host, path)
        out = json.dumps({
            "version": VER, "python": PYVER,
            "host_repr": repr(host), "path_repr": repr(path),
            "stage": stage, "flag_echo": flag_echo,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def main():
    threading.Thread(target=_flag_server, daemon=True).start()
    time.sleep(0.3)
    print("[canary %s] flag listener on 127.0.0.1:%d (loopback only)" % (VER, FLAG_PORT), flush=True)
    srv = ThreadingHTTPServer(("0.0.0.0", APP_PORT), _Handler)
    print("[harness %s] python %s control server on 0.0.0.0:%d" % (VER, PYVER, APP_PORT), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
