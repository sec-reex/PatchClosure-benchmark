#!/usr/bin/env python3
"""[GIVEN] CVE-2026-32808 seed exploit — path traversal in SevenZip.verify().

pyLoad's SevenZip password-verification path derives an archive entry name from
`7z l` output and (in verify()) does `os.remove(os.path.join(self.dest, entry))`
with no traversal check, so an attacker-controlled 7z entry name of the form
`../<dir>/<file>` deletes a file OUTSIDE the extraction directory (arbitrary file
deletion, CVSS 8.1). We represent the seed by its attacker-controlled entry name;
the version environment replicates verify()'s join-then-remove against a planted
out-of-bounds delete-canary using THAT version's real join primitive.

Contract:  works on V0 (os.path.join -> canary DELETED)  ;  BLOCKED on V1, where
the CVE-2026-32808 fix (commit 5f4f0fa) routes verify() through fs.safejoin(),
which raises on the traversal (canary SURVIVES).
"""
from __future__ import annotations

# 7z entry name that escapes the extraction dir to a sibling location.
SEED_ENTRY = "../seed_evil/DELME.txt"


def candidate() -> dict:
    return {"probe_id": "cve-2026-32808-7z-verify-delete", "sink": "seed", "entry": SEED_ENTRY}


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
