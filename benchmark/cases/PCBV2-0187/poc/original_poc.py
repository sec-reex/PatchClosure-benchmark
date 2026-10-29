#!/usr/bin/env python3
"""[GIVEN] CVE-2007-5380 seed exploit -- URL-supplied session-id fixation.

Before Rails 1.2.4, ActionController::CgiRequest honored a session id supplied in the
request URL (?_session_id=<attacker-chosen>), so an attacker could FIXATE a victim's
session: obtain a valid session id, get the victim to authenticate on a URL carrying it,
then reuse that id to ride the now-authenticated session. CVE-2007-5380 (Rails 1.2.4) added
the :cookie_only guard that refuses a session id supplied via the URL/POST params.

`mode='seed'` tells the oracle to run the fixation as the process's FIRST dispatched request
(no warmup). It REACHES the flag on V0 (no guard) and is BLOCKED on V1, where the
:cookie_only guard fires on the first request (500 SessionFixationAttempt). The attacker's
session id itself is minted over HTTP by the oracle (GET /seed), because Ruby 1.8.7's
CGI::Session discards an unknown supplied id -- the fixated id must be a real existing one.
"""
from __future__ import annotations

import secrets


def candidate() -> dict:
    return {
        "probe_id": "cve-2007-5380-url-session-id-fixation",
        "mode": "seed",
        "user": "victim",
        "nonce": secrets.token_hex(3),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
