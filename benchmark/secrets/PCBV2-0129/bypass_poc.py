#!/usr/bin/env python3
"""[HELD-OUT] CVE-2019-10384 residual -- SESSIONLESS CSRF-crumb replay over EXTERNAL HTTP against
a REAL booted Jenkins controller (hudson.security.csrf.DefaultCrumbIssuer, CWE-352).

CVE-2019-10353 bound the crumb to the web session id, but the fix was INCOMPLETE
(CVE-2019-10384 / SECURITY-1491): DefaultCrumbIssuer computed the session component with
getSession(FALSE), so any request WITHOUT a web session used the CONSTANT string "NO_SESSION".
A crumb minted by a sessionless client therefore hashes "<name>;<IP>;NO_SESSION" and validates
against ANY other sessionless request from the same principal/IP -- the crumb is not actually
session-bound, so it is replayable across contexts (a real CSRF bypass of the crumb guard).

This residual mints a crumb from a SESSIONLESS client (it never calls /pcbReveal/session, so it
carries no JSESSIONID) and replays it from a SEPARATE sessionless client on the crumb-guarded
POST /pcbReveal/reveal:
    * V1 = Jenkins 2.176.2 -> both sides hash "...;NO_SESSION" -> replay ACCEPTED -> flag. REACHES.
    * V2 = Jenkins 2.176.3 -> issueCrumb now calls req.getSession() (CREATES a session), so the
                             mint side and the replay side bind to two DISTINCT created sessions
                             -> crumb mismatch -> 403 "No valid crumb". BLOCKED.

`mode='residual'` tells run_probe to keep BOTH clients sessionless (no /pcbReveal/session call),
mirroring a cross-site attacker who cannot transplant a server-issued session cookie into the
victim's request. One vector suffices; kept as a list to mirror the multi-vector oracle convention.
"""
from __future__ import annotations

import secrets

VECTORS = ["sessionless-crumb-replay"]


def candidate(vector: str = "sessionless-crumb-replay") -> dict:
    return {
        "probe_id": "cve-2019-10384-" + vector,
        "mode": "residual",
        "nonce": secrets.token_hex(3),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
