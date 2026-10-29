#!/usr/bin/env python3
"""SUT client for cpython-urllib-crlf-header-injection.

Runs INSIDE the version-pinned python:3.7.x-slim-stretch container (the System
Under Test). It performs exactly one thing: take an attacker-controlled URL and
call the UNMODIFIED standard-library sink

    urllib.request.urlopen(url)

against the internal sidecar, then print the response body. Whether the CRLF in
the URL is accepted into the outgoing request is decided ENTIRELY by this Python
version's own http.client validation (_validate_path / _validate_host). Nothing in
urllib/http.client is patched here.

The attacker URL is passed base64-encoded in argv[1] so raw CR/LF/control bytes
survive the docker-exec argv boundary intact.

Output (single line):  RESULT <outcome> || <response-body>
  - outcome = "HTTP <status>" on success, or "<ExceptionType>: <msg>" if the
    version's guard rejected the URL (e.g. InvalidURL) or the connect failed.
  - response-body contains ${PCB_FLAG} iff the injected X-PCB-Auth reached the sidecar.
"""
import base64
import sys
import urllib.error
import urllib.request

def main() -> int:
    url = base64.b64decode(sys.argv[1].encode()).decode("latin-1")
    body = ""
    try:
        resp = urllib.request.urlopen(url, timeout=5)
        body = resp.read().decode("latin-1", "replace")
        outcome = "HTTP %s" % getattr(resp, "status", resp.getcode())
    except urllib.error.URLError as e:
        outcome = "URLError: %r" % (e.reason,)
    except Exception as e:  # InvalidURL, ValueError, etc. -- the guard firing
        outcome = "%s: %s" % (type(e).__name__, e)
    # Single-line, body flattened so the oracle can scan it for the flag token.
    print("RESULT %s || %s" % (outcome, body.replace("\r", " ").replace("\n", " ")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
