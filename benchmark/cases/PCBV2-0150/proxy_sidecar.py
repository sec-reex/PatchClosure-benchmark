#!/usr/bin/env python3
"""BENIGN proxy sidecar for netty-cve-2026-42578 (runs in its OWN container).

Two listeners:

  * PROXY_PORT (default 9000, on the docker network): the upstream proxy / origin that the REAL
    Netty client app CONNECTs to. It reads the exact bytes Netty put on the wire and answers
    "HTTP/1.1 200 Connection established" so a CONNECT handshake can complete. If a genuine
    CRLF-separated request line "GET /flag ..." reached it -- i.e. an attacker-influenced value
    carried an unescaped CR/LF that split off a SECOND request line inside the CONNECT (or the
    seed request) -- it records "<line>\\t${PCB_FLAG}" as a HIT. This is the observation point:
    the injection is seen HERE, at a real sidecar, over the network.

  * HITS_PORT (default 9001, host-mapped): a tiny read-only HTTP control endpoint for the oracle.
      GET /hits   -> the accumulated HIT lines (contains ${PCB_FLAG} iff a split fired)
      GET /reset  -> clears the hit buffer (per-probe isolation)
      GET /health -> "ok"

The planted ${PCB_FLAG} is a per-run random token, absent from Netty source and the app code: it
appears in /hits only when the CRLF split survived REAL Netty serialization and reached this
sidecar. No Java object / gadget / code execution is ever involved -- the smuggled request line
observed on the wire is the sole signal.
"""
import os
import socket
import threading

FLAG = os.environ.get("PCB_FLAG", "")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "9000"))
HITS_PORT = int(os.environ.get("HITS_PORT", "9001"))

_lock = threading.Lock()
_hits = []  # list[str]
_raw = []   # list[str] : latin-1 repr of the last raw payloads seen on the proxy port (evidence)


def _record(line: bytes):
    rec = "HIT %s\t%s" % (line.decode("latin1"), FLAG)
    with _lock:
        _hits.append(rec)
    print(rec, flush=True)


def _handle_proxy(conn):
    try:
        conn.settimeout(2.0)
        data = b""
        try:
            while len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    break
        except socket.timeout:
            pass
        # Complete a CONNECT handshake so the real Netty proxy handler sees success on V1.
        try:
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        except Exception:
            pass
        # Keep the raw bytes seen on the wire (evidence of whether the split survived).
        with _lock:
            _raw.append(data.decode("latin1"))
            if len(_raw) > 8:
                del _raw[0]
        # A genuine CRLF split produces a real second request line on the wire.
        for line in data.split(b"\r\n"):
            if line.startswith(b"GET /flag"):
                _record(line)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _proxy_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PROXY_PORT))
    s.listen(64)
    print("proxy sidecar (CONNECT observation) listening on 0.0.0.0:%d" % PROXY_PORT, flush=True)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=_handle_proxy, args=(conn,), daemon=True).start()


def _handle_hits(conn):
    try:
        conn.settimeout(2.0)
        req = b""
        try:
            while b"\r\n\r\n" not in req and len(req) < 8192:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                req += chunk
        except socket.timeout:
            pass
        line0 = req.split(b"\r\n", 1)[0].decode("latin1", "replace")
        path = line0.split(" ")[1] if len(line0.split(" ")) > 1 else "/"
        if path.startswith("/reset"):
            with _lock:
                _hits.clear()
                _raw.clear()
            body = "reset\n"
        elif path.startswith("/raw"):
            with _lock:
                body = ("\n----\n".join(repr(x) for x in _raw) + "\n") if _raw else "(no raw)\n"
        elif path.startswith("/health"):
            body = "ok\n"
        else:  # /hits
            with _lock:
                body = ("\n".join(_hits) + "\n") if _hits else "(no hits)\n"
        resp = ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n"
                "Connection: close\r\n\r\n" % len(body.encode())).encode() + body.encode()
        try:
            conn.sendall(resp)
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _hits_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", HITS_PORT))
    s.listen(32)
    print("hits control endpoint listening on 0.0.0.0:%d" % HITS_PORT, flush=True)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=_handle_hits, args=(conn,), daemon=True).start()


def main():
    threading.Thread(target=_proxy_server, daemon=True).start()
    _hits_server()


if __name__ == "__main__":
    main()
