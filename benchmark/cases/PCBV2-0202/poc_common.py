#!/usr/bin/env python3
"""Shared EXTERNAL-HTTP orchestration for ssti_thymeleaf_spel_sandbox.

One "probe" = a single external HTTP request that sends a user-controlled `expr` to the version's
REAL Spring Boot web app `GET/POST /render`. The controller inlines `expr` into the RESTRICTED
preprocessing position `__${...}__` of a Thymeleaf view and renders it with the REAL, unmodified
thymeleaf-spring6 pinned per version. The observable result is the HTTP response body; the per-run
${PCB_FLAG} appears in it IFF that version's own restricted-context keyword scanner let the escape
instantiate pcb.PcbFlagReader() (whose constructor reads the planted /flag). Nothing in
Thymeleaf/Spring is modified -- the version booted per env (v0/v1/v2) is the only guard.
"""
import urllib.parse
import urllib.request
import urllib.error

# Host-published ports (oracle / PoCs run on the host and reach the app EXTERNALLY over HTTP).
HOST_APP = {
    "v0": "http://127.0.0.1:18413",   # thymeleaf 3.1.3.RELEASE
    "v1": "http://127.0.0.1:18414",   # thymeleaf 3.1.4.RELEASE  (target)
    "v2": "http://127.0.0.1:18415",   # thymeleaf 3.1.5.RELEASE  (negative)
}


def post_render(expr: str, version: str, timeout: int = 30) -> dict:
    """External HTTP POST of a user-controlled `expr` to `version`'s /render. Returns
    {status, body}."""
    url = HOST_APP[version] + "/render"
    data = urllib.parse.urlencode({"expr": expr}).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode("utf-8", "replace")}


def health(version: str, timeout: int = 3) -> bool:
    try:
        with urllib.request.urlopen(HOST_APP[version] + "/health", timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False
