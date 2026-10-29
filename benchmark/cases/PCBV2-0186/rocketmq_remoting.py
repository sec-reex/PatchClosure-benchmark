#!/usr/bin/env python3
"""Minimal RocketMQ remoting protocol client (binary TCP).

Implements just enough of the RocketMQ 4.x/5.x remoting protocol to send
UPDATE_NAMESRV_CONFIG (code 318), GET_NAMESRV_CONFIG (code 319), and
PUT_KV_CONFIG (code 100) requests.

Protocol layout (big-endian):
  [4 bytes total_len] [4 bytes header_len] [header JSON] [body bytes]

Header JSON fields: code, language, version, opaque, flag, remark, extFields.
Body for config update: Java Properties format "key=value\\n".

This is a standalone helper for the PatchClosure-Bench oracle -- no external
dependencies beyond the Python stdlib.
"""
from __future__ import annotations

import json
import socket
import struct
import threading

# Request codes (from org.apache.rocketmq.remoting.protocol.RequestCode)
PUT_KV_CONFIG = 100
UPDATE_NAMESRV_CONFIG = 318
GET_NAMESRV_CONFIG = 319

_opaque_counter = 0
_opaque_lock = threading.Lock()


def _next_opaque() -> int:
    global _opaque_counter
    with _opaque_lock:
        _opaque_counter += 1
        return _opaque_counter


def _encode_request(code: int, body: bytes | None = None,
                    ext_fields: dict | None = None) -> bytes:
    """Encode a RocketMQ remoting request frame."""
    header = {
        "code": code,
        "language": "JAVA",
        "version": 401,
        "opaque": _next_opaque(),
        "flag": 0,
        "remark": "",
        "extFields": ext_fields or {},
    }
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    body_bytes = body or b""
    header_len = len(header_bytes)
    total_len = 4 + header_len + len(body_bytes)
    return struct.pack(">II", total_len, header_len) + header_bytes + body_bytes


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed while reading")
        buf += chunk
    return buf


def _decode_response(sock: socket.socket, timeout: float = 10.0) -> dict:
    """Read and decode one RocketMQ remoting response."""
    sock.settimeout(timeout)
    raw_len = _recv_exact(sock, 4)
    total_len = struct.unpack(">I", raw_len)[0]
    payload = _recv_exact(sock, total_len)
    header_len = struct.unpack(">I", payload[:4])[0] & 0x00FFFFFF
    header_json = payload[4:4 + header_len]
    body = payload[4 + header_len:]
    resp = json.loads(header_json)
    resp["_body"] = body.decode("utf-8", errors="replace") if body else ""
    return resp


def send_request(host: str, port: int, code: int,
                 body: bytes | None = None, ext_fields: dict | None = None,
                 timeout: float = 10.0) -> dict:
    """Open a TCP connection, send one request, read one response, close."""
    frame = _encode_request(code, body, ext_fields)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(frame)
        return _decode_response(s, timeout)


def update_namesrv_config(host: str, port: int, properties: dict[str, str],
                          timeout: float = 10.0) -> dict:
    """Send UPDATE_NAMESRV_CONFIG with the given properties dict."""
    body = "\n".join(f"{k}={v}" for k, v in properties.items()).encode("utf-8")
    return send_request(host, port, UPDATE_NAMESRV_CONFIG, body=body, timeout=timeout)


def get_namesrv_config(host: str, port: int, timeout: float = 10.0) -> dict:
    """Send GET_NAMESRV_CONFIG and return the response (config in _body)."""
    return send_request(host, port, GET_NAMESRV_CONFIG, timeout=timeout)


def put_kv_config(host: str, port: int, namespace: str, key: str, value: str,
                  timeout: float = 10.0) -> dict:
    """Send PUT_KV_CONFIG to store a KV pair (triggers KV persist)."""
    ext = {"namespace": namespace, "key": key, "value": value}
    return send_request(host, port, PUT_KV_CONFIG, ext_fields=ext, timeout=timeout)
