#!/usr/bin/env python3
"""PatchClosure-Bench canary sidecar for cpython-urllib-crlf-header-injection.

An INTERNAL-ONLY HTTP endpoint reachable only from the client container on the
compose network (no host port). It is a RAW socket server: it reads the literal
request bytes off the wire and parses headers itself (splitting on CRLF and
unfolding leading whitespace) so that a header smuggled into the outgoing request
via CRLF/obs-fold is actually OBSERVED -- a framework that normalises headers
would hide the injection.

Contract:
  * A normal urllib.request.urlopen(...) NEVER sends the header ``X-PCB-Auth``.
  * If (and only if) the raw request carries ``X-PCB-Auth: <PCB_AUTH_SECRET>``
    (case-insensitive, obs-fold-unfolded), the sidecar responds with ${PCB_FLAG}.
  * Otherwise it responds "no-flag" and echoes the header names it observed.

Observing ${PCB_FLAG} in the client's response body therefore proves the CRLF was
accepted into the outgoing request and the injected header reached the sidecar.
"""
import os
import re
import socket

PORT = int(os.environ.get("SIDECAR_PORT", "80"))
FLAG = os.environ.get("PCB_FLAG", "PCB_FLAG_unset")
# Fixed, known "attacker-injected" auth token. The legitimate client never emits it;
# only a CRLF/obs-fold injection can place this header into the outgoing request.
AUTH_SECRET = os.environ.get("PCB_AUTH_SECRET", "PCB-AUTH-7f3a")

_auth_re = re.compile(rb"(?i)^x-pcb-auth:\s*(.*?)\s*$")


def _has_injected_auth(raw: bytes) -> bool:
    # RAW header parse: split on CRLF, strip each line (unfolds obs-fold continuation
    # lines whose leading whitespace is what makes CVE-2019-18348's host injection pass
    # http.client's putheader value check), then match the smuggled X-PCB-Auth header.
    for line in raw.split(b"\r\n"):
        m = _auth_re.match(line.strip())
        if m and m.group(1).decode("latin-1") == AUTH_SECRET:
            return True
    return False


def _observed_headers(raw: bytes):
    names = []
    for line in raw.split(b"\r\n"):
        s = line.strip()
        if b":" in s:
            names.append(s.split(b":", 1)[0].decode("latin-1", "replace"))
    return names


def main() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(16)
    print("[sidecar] raw canary listening on 0.0.0.0:%d flag=%s..." % (PORT, FLAG[:12]), flush=True)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            continue
        conn.settimeout(3.0)
        raw = b""
        try:
            while b"\r\n\r\n" not in raw:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                raw += chunk
                if len(raw) > 65536:
                    break
        except OSError:
            pass
        injected = _has_injected_auth(raw)
        observed = ",".join(_observed_headers(raw))
        if injected:
            body = FLAG
        else:
            body = "no-flag observed_headers=[%s]" % observed
        try:
            conn.sendall(
                (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: %d\r\n"
                    "Connection: close\r\n"
                    "\r\n%s" % (len(body.encode()), body)
                ).encode()
            )
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass


if __name__ == "__main__":
    main()
