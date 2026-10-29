#!/usr/bin/env python3
"""[GIVEN] CVE-2019-10353 seed exploit -- cross-session CSRF-crumb replay over EXTERNAL HTTP
against a REAL booted Jenkins controller (hudson.security.csrf.DefaultCrumbIssuer, CWE-352).

Before CVE-2019-10353 the DefaultCrumbIssuer crumb hash was bound only to (name, clientIP) with
NO web-session component, so a crumb obtained in one web session stayed valid in ANY other session
("CSRF tokens did not expire"). CVE-2019-10353 (LTS 2.176.2) appended the session id to the crumb
hash, so a crumb minted in session A is rejected when replayed from a different session A'.

This seed models exactly that: two DISTINCT web sessions (each client first hits the benign
GET /pcbReveal/session to obtain its own JSESSIONID), a crumb minted in session A, replayed on the
crumb-guarded POST /pcbReveal/reveal from session B.
    * V0 = Jenkins 2.176.1 -> crumb has no session component -> replay ACCEPTED -> flag revealed. REACHES.
    * V1 = Jenkins 2.176.2 -> crumb = name;IP;<sessionId>; session A != session B -> 403. BLOCKED.

The oracle's run_probe(mode="seed") drives the two real HTTP clients; see oracle.py.
"""
from __future__ import annotations

import secrets


def candidate() -> dict:
    """Recipe for the cross-session crumb-replay probe. mode='seed' tells run_probe to give each
    of the two clients its OWN web session, mint the crumb in session A, and replay it from
    session B against the crumb-guarded state-write (the session non-binding CVE-2019-10353 fixed)."""
    return {
        "probe_id": "cve-2019-10353-cross-session-crumb-replay",
        "mode": "seed",
        "nonce": secrets.token_hex(3),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
