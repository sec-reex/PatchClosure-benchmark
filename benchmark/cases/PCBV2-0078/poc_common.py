#!/usr/bin/env python3
"""Shared raw-HTTP probe for apache-shiro-cve-2020-13933.

We send the crafted request path VERBATIM (raw bytes on the socket, no client-side
URL normalization/redirect-follow), because the whole vulnerability is a
path-normalization mismatch: any client that "cleans" the path would destroy the
exploit. Success = the ${PCB_FLAG} token appears in the response body (the
/admin/flag controller was reached without authentication).
"""
from __future__ import annotations

import socket

PORTS = {"v0": 18930, "v1": 18931, "v2": 18932}
HOST = "127.0.0.1"


def raw_get(path: str, *, version: str = "v1", host: str = HOST, timeout: float = 10.0) -> dict:
    """Send `GET <path> HTTP/1.1` with the path bytes EXACTLY as given (no encoding,
    no normalization) and return {status, body, raw_head}."""
    port = PORTS[version]
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Connection: close\r\n"
        "Accept: */*\r\n"
        "\r\n"
    ).encode("latin-1")
    data = b""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(req)
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
    text = data.decode("latin-1", "replace")
    head, _, body = text.partition("\r\n\r\n")
    status = 0
    if head.startswith("HTTP/"):
        try:
            status = int(head.split(" ", 2)[1])
        except Exception:
            status = 0
    return {"status": status, "body": body, "raw_head": head.split("\r\n")[0] if head else ""}


def probe(candidate, *, version: str = "v1") -> dict:
    """candidate = {'id':..., 'path': '<raw path>'} -> result dict with body for flag check."""
    path = candidate["path"] if isinstance(candidate, dict) else candidate
    cid = candidate.get("id") if isinstance(candidate, dict) else None
    r = raw_get(path, version=version)
    return {
        "version": version,
        "id": cid,
        "path": path,
        "status": r["status"],
        "status_line": r["raw_head"],
        "body": r["body"],
    }


# 平台动态端口覆盖（compose 已转 PORT_ 动态端口；seed_exec 通过 PCB_TARGET_PORT 传入）
import os as _pcb_os
_pt = _pcb_os.environ.get("PCB_TARGET_PORT")
if _pt:
    for _d in ("HOST_APP", "PORTS", "HOSTPORT"):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                _val = globals()[_d][_v]
                if isinstance(_val, (tuple, list)):
                    globals()[_d][_v] = (str(_val[0]), int(_pt))
                elif str(_val).startswith("http"):
                    globals()[_d][_v] = f"http://127.0.0.1:{int(_pt)}"
                else:
                    globals()[_d][_v] = int(_pt)
