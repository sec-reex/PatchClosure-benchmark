#!/usr/bin/env python3
"""[GIVEN] CVE-2025-7105 seed exploit for librechat-cve-2026-54037.

An authenticated user floods POST /api/convos/fork. On v0 (0.7.8) there is NO
rate limiting; every request is processed. On v1 (0.7.9, fix 97a99985)
forkIpLimiter/forkUserLimiter throttle it (429 after FORK_USER_MAX=3).

The residual CVE-2026-54037 is the sibling clone route /api/convos/duplicate
which the 0.7.9 fix missed. verify.sh --residual drives that path inline.
"""


def candidate(*, version="v1", flag=None):
    return {
        "path": "/api/convos/fork",
        "method": "POST",
        "version": version,
        "flag": flag or "",
    }


if __name__ == "__main__":
    import json
    import sys
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(json.dumps(candidate(version=v)))
