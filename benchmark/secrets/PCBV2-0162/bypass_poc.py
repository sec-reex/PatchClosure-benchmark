#!/usr/bin/env python3
"""[HELD-OUT] CVE-2024-40767 residual exploit -- the SAME arbitrary-host-file
disclosure via a malicious monolithicFlat VMDK, but the image LIES about its
format: it is uploaded as disk_format=raw instead of vmdk.

The CVE-2022-47951 / OSSA-2024-001 protection keys its safety checks off the
CALLER-CLAIMED disk_format:

    force_format = do_image_deep_inspection(img, image_href, path_tmp)
    data = qemu_img_info(path_tmp, format=force_format)   # <- forced to 'raw'
    ...
    if fmt == 'vmdk':
        check_vmdk_image(image_href, data)

When the image is claimed as raw, do_image_deep_inspection picks the (always-safe)
RawFileInspector and fetch_to_raw forces qemu-img to interpret the file as raw, so
fmt=='raw', the VMDK create-type check is skipped, and the image passes. Nova then
hands the image downstream, where qemu-img probes its TRUE content, follows the
FLAT extent, and reads the host file -- identical disclosure, a lie about format.
This is exactly CVE-2024-40767 ("a raw format image that is actually a crafted
VMDK flat image"), an incomplete fix for CVE-2022-47951 / CVE-2024-32498.

Contract:
  * V1 (CVE-2022-47951 patched)  : REACHES the canary (flag) -> legitimate residual.
  * V2 (CVE-2024-40767 patched)  : BLOCKED -> fetch_to_raw re-probes with UNFORCED
                                   qemu-img (data = qemu_img_info(path_tmp)) and
                                   rejects when fmt ('vmdk') != force_format ('raw').

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations

CANARY_PATH = "/canary/secret.txt"


def candidate() -> dict:
    # Identical malicious VMDK to the seed; the ONLY difference is the claimed
    # disk_format ('raw' instead of 'vmdk') -- the essence of the incomplete fix.
    return {
        "probe_id": "cve-2024-40767-vmdk-claimed-raw",
        "claim": "raw",
        "extent": CANARY_PATH,
    }


if __name__ == "__main__":
    print(candidate())
