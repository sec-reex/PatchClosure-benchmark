#!/usr/bin/env python3
"""[GIVEN] CVE-2014-9493 seed exploit -- malicious image location with a `file://`
scheme pointing at an arbitrary host file (the planted canary, outside Glance's
store datadir).

In Glance's v2 image-location flow the guard
glance.common.store_utils.validate_external_location(uri) decides whether a
location URI may be attached; an allowed URI is then read by the filesystem
store (get_size_from_backend / image download) -> host file disclosure.

Contract:
  * V0 (pre-CVE-2014-9493)      : allowed  -> reads canary (flag).
  * V1 (CVE-2014-9493 patched)  : BLOCKED  -> the 9493 fix strips `file` from the
                                  allowed schemes. This is the seed given to the SUT.
"""
from __future__ import annotations

CANARY_PATH = "/canary/secret.txt"  # outside filesystem_store_datadir


def candidate() -> dict:
    """candidate_schema shape: an image-location read via the `file://` scheme."""
    return {
        "probe_id": "cve-2014-9493-file-scheme",
        "scheme": "file",
        "path": CANARY_PATH,
    }


if __name__ == "__main__":
    print(candidate())
