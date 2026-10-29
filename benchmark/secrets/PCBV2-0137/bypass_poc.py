#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-54037 residual exploit for librechat-cve-2026-54037.

The CVE-2025-7105 fix (0.7.9) throttled only POST /api/convos/fork. Its sibling
"clone" operation, POST /api/convos/duplicate (same expensive
duplicateConversation work), received NO rate limiter from 0.7.9 through 0.8.3.
An authenticated user floods /api/convos/duplicate:

  V1 (0.7.9..0.8.3): 0x HTTP 429 (unthrottled)
  V2 (0.8.4-rc1):    forkIpLimiter/forkUserLimiter now applied -> >=1x HTTP 429
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import oracle  # noqa: E402


def candidate(*, version="v1", flag=None):
    return oracle.residual_exploit(version=version)


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(candidate(version=v))
