#!/usr/bin/env python3
"""[GIVEN] CVE-2023-48223 seed: HS256 forged with HMAC secret = the server's
PKCS1 RSA PUBLIC key (whitespace stripped) -> grants /admin on V0 (server trusts
the RSA public key bytes as an HMAC secret); blocked on V1 (fast-jwt 3.3.2
classifies the key as RSA and refuses HS256). Thin wrapper around oracle.original_poc.
"""
from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oracle import original_poc  # noqa: E402

if __name__ == "__main__":
    import json
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(json.dumps(original_poc(version=v)))
