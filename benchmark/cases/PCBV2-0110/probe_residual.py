#!/usr/bin/env python3
"""Probe V1 (5.3.6) /parse with an arbitrary XML body, measuring external round-trip latency.
Usage: probe_residual.py '<xml>' [port]
Fresh-server lifecycle handled by the caller (kill + up -d before each probe)."""
import http.client, json, socket, sys, time
payload = sys.argv[1] if len(sys.argv) > 1 else "<r>hi</r>"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 34921
TO = 10.0
data = payload.encode("utf-8")
t0 = time.perf_counter()
try:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=TO)
    c.request("POST", "/parse", body=data,
              headers={"Content-Type": "text/xml", "Content-Length": str(len(data))})
    r = c.getresponse()
    resp = r.read().decode("utf-8", "replace")
    c.close()
    ms = (time.perf_counter() - t0) * 1000.0
    print(json.dumps({"in_len": len(payload), "latency_ms": round(ms,1), "timeout": False, "resp": resp[:200]}))
except (socket.timeout, TimeoutError):
    ms = (time.perf_counter() - t0) * 1000.0
    print(json.dumps({"in_len": len(payload), "latency_ms": round(max(ms,10000),1), "timeout": True, "resp": None}))
