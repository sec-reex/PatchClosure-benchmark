#!/usr/bin/env python3
"""[HELD-OUT] CVE-2007-6077 residual -- session-id fixation after one warmup request.

CVE-2007-5380 (Rails 1.2.4) added `:cookie_only => true` and the guard
    if @cookie_only && request_parameters[session_key]
      raise SessionFixationAttempt
to refuse a URL-supplied session id. But the fix was INCOMPLETE (CVE-2007-6077):
CgiRequest#initialize did `@cookie_only = session_options.delete :cookie_only`, and the
WEBrick dispatcher passes the SHARED DEFAULT_SESSION_OPTIONS constant, so `.delete` mutates
it -- only the FIRST request of the process ever sees :cookie_only. From the second request
on, @cookie_only == nil, the guard is inert, and the URL `_session_id` is honored again ->
the exact fixation the earlier patch was meant to stop still works on a warmed process.

`mode='residual'` tells the oracle to issue ONE benign warmup request (GET /, which trips the
`session_options.delete` mutation) BEFORE the fixation. It REACHES the flag on V1 (guard now
inert) and is BLOCKED on V2 (Rails 1.2.6 re-derives cookie_only? fresh each request, so the
warmup cannot disable it). The fixated id is minted over HTTP by the oracle (GET /seed).
"""
from __future__ import annotations

import secrets


def candidate() -> dict:
    return {
        "probe_id": "cve-2007-6077-warmed-url-session-id-fixation",
        "mode": "residual",
        "user": "victim",
        "nonce": secrets.token_hex(3),
    }


if __name__ == "__main__":
    print(candidate())
