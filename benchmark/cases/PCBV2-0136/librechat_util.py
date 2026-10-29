"""Shared plumbing for LibreChat benchmark cases (register/login + probe endpoints)."""

import json
import os
import re
import time
import uuid
import zlib
import struct
import requests

BASE = {
    "librechat-cve-2026-54024": {
        "v0": "http://127.0.0.1:53710",
        "v1": "http://127.0.0.1:53711",
        "v2": "http://127.0.0.1:53712",
    },
    "librechat-cve-2026-54037": {
        "v0": "http://127.0.0.1:53720",
        "v1": "http://127.0.0.1:53721",
        "v2": "http://127.0.0.1:53722",
    },
}

USER_EMAIL = "pcb@pcb.local"
USER_PASS = "PcbPass123!"


def _png_chunk(tag: bytes, data: bytes) -> bytes:
    c = struct.pack(">I", len(data)) + tag + data
    return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)


def make_png(path: str, width: int = 2048, height: int = 1024, raw_extra: int = 0) -> None:
    """A valid PNG whose encoded size is >= ~5MB (raw RGB + zlib + padding chunk)."""
    raw = bytearray()
    for _ in range(height):
        raw += b"\x00"  # filter byte
        raw += os.urandom(width * 3)
    if raw_extra:
        raw += b"\x00" + os.urandom(raw_extra)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress(bytes(raw), 9)
    png = (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", idat)
        + _png_chunk(b"IEND", b"")
    )
    with open(path, "wb") as f:
        f.write(png)


def make_import_json(path: str, target_bytes: int) -> None:
    """LibreChat linear export format, padded with a large user message to exceed a size limit."""
    msg = {
        "messageId": str(uuid.uuid4()),
        "conversationId": "4c9e1402-f746-479d-8a18-2dfab1bf750f",
        "createdAt": "2024-05-29T00:33:03.661Z",
        "endpoint": "azureOpenAI",
        "error": False,
        "isCreatedByUser": True,
        "isEdited": False,
        "model": None,
        "parentMessageId": None,
        "sender": "user",
        "text": "A" * (target_bytes - 2000),
        "unfinished": False,
        "updatedAt": "2024-05-29T00:33:03.661Z",
    }
    data = {
        "conversationId": "4c9e1402-f746-479d-8a18-2dfab1bf750f",
        "endpoint": "azureOpenAI",
        "title": "PCB benchmark import",
        "exportAt": "20:33:31 GMT-0400 (Eastern Daylight Time)",
        "branches": False,
        "recursive": False,
        "messages": [msg],
    }
    blob = json.dumps(data).encode()
    if len(blob) < target_bytes:
        # pad inside the message text to reach the requested size exactly
        msg["text"] = "A" * (target_bytes - (len(blob) - len(msg["text"])) - 16)
        blob = json.dumps(data).encode()
    with open(path, "wb") as f:
        f.write(blob)


def wait_http(base: str, path: str = "/", timeout: int = 300) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(base + path, timeout=8)
            if r.status_code < 500:
                return True
        except Exception:
            pass
        time.sleep(4)
    return False


def login(base: str, email: str = USER_EMAIL, password: str = USER_PASS) -> dict:
    r = requests.post(
        base + "/api/auth/login",
        json={"email": email, "password": password},
        timeout=20,
    )
    if r.status_code != 200:
        return {"error": r.text[:200], "status": r.status_code}
    d = r.json()
    return {"token": d.get("token"), "status": r.status_code}


def ensure_user(base: str) -> dict:
    """Register (if needed) then login. Returns token or error dict."""
    requests.post(
        base + "/api/auth/register",
        json={
            "name": "pcbuser",
            "email": USER_EMAIL,
            "password": USER_PASS,
            "confirm_password": USER_PASS,
        },
        timeout=20,
    )
    for _ in range(6):
        lr = login(base)
        if "token" in lr:
            return lr
        time.sleep(3)
    return lr


def wait_ready(base: str, timeout: int = 420) -> bool:
    """App up AND a seeded user can log in (registers if needed)."""
    if not wait_http(base, timeout=timeout):
        return False
    return "token" in ensure_user(base)
