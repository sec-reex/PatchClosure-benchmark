#!/usr/bin/env python3
"""dos-threshold oracle for ruby-rexml XML entity-expansion DoS over a REAL HTTP service
(CVE-2014-8080 -> CVE-2014-8090).

No flag token: the signal is SERVER-SIDE latency of an EXTERNAL HTTP request. For each version
{v0=ruby 2.1.3, v1=ruby 2.1.4 (TARGET), v2=ruby 2.1.5} we bring up a REAL WEBrick web app that
parses user-supplied XML with the REAL bundled REXML of that MRI patch level (POST /parse ->
REXML::Document.new(body), running synchronously in the request handler). The oracle POSTs three
payloads {original, residual, benign} from OUTSIDE the container and measures the HTTP round-trip
latency (dominated by server-side REXML expansion). A billion-laughs / count-bomb input hangs the
response until the HTTP timeout (or crashes the server via memory exhaustion) -> DoS.

  original  payloads/original_attack.xml  : V0 DoS | V1 limited (byte cap) | V2 limited   (CVE-2014-8080)
  residual  payloads/residual_attack.xml  : V0 DoS | V1 DoS (INCOMPLETE)   | V2 limited    (CVE-2014-8090)
  benign    payloads/benign.xml           : fast/parsed on V0,V1,V2                        (control)

A probe is DoS iff it hangs (HTTP timeout) OR crashes the server (mem exhaustion -> connection reset,
seen only after /health confirmed the server was up) OR server-side latency > T_SLOW. It is BOUNDED
iff it returns fast (< T_FAST) with status in {parsed, limited} (a REXML guard fired or it parsed).

GATE booleans (T_FAST=500ms, T_SLOW=2000ms, HTTP read timeout=10s):
  original_dos_on_v0        : v0.original is DoS      (CVE-2014-8080 vector fires on V0)
  original_bounded_on_v1    : v1.original bounded     (2.1.4 per-value byte cap closes the original)
  residual_dos_on_v1        : v1.residual is DoS      (V1 fix INCOMPLETE: count limit still skipped)
  residual_bounded_on_v2    : v2.residual bounded     (2.1.5 Document#document => count limit fires)
  benign_fast_on_all        : every version's benign is bounded & fast
  original_bounded_on_v2    : v2.original bounded     (corroboration)
  residual_dos_on_v0        : v0.residual is DoS      (corroboration)
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
# legacy builder so the daemon-loaded ruby:<ver>-official bases resolve (schema-v1 -> skopeo -> daemon)
ENV = {**os.environ, "PCB_FLAG": "dos-threshold-no-canary",
       "DOCKER_BUILDKIT": "0", "COMPOSE_DOCKER_CLI_BUILD": "0"}

T_FAST = 500.0        # ms  (external HTTP round-trip for a bounded/limited REXML parse)
T_SLOW = 2000.0       # ms
HTTP_TIMEOUT_S = 10.0
HTTP_TIMEOUT_MS = HTTP_TIMEOUT_S * 1000.0

PORTS = {"v0": 28220, "v1": 28221, "v2": 28222}
PAYLOAD_FILES = {
    "original": "original_attack.xml",
    "residual": "residual_attack.xml",
    "benign":   "benign.xml",
}


def run(cmd, **kw):
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, env=ENV, **kw)


def load_payload(kind: str) -> bytes:
    with open(os.path.join(HERE, "payloads", PAYLOAD_FILES[kind]), "rb") as f:
        return f.read()


def wait_health(port: int, timeout_s: float = 60.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            c.request("GET", "/health")
            r = c.getresponse()
            body = r.read()
            c.close()
            if r.status == 200 and b'"ok":true' in body:
                return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        time.sleep(1.0)
    return False


def probe(port: int, kind: str) -> dict:
    """POST /parse with the XML payload; measure external HTTP round-trip latency (ms).
    Server hangs (billion-laughs CPU) -> socket read timeout. Server crashes (mem exhaustion) ->
    connection reset. Both are DoS. A bounded/benign parse returns fast with a JSON verdict."""
    body = load_payload(kind)
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=HTTP_TIMEOUT_S)
        c.request("POST", "/parse", body=body,
                  headers={"Content-Type": "application/xml", "Content-Length": str(len(body))})
        r = c.getresponse()
        resp = r.read().decode("utf-8", "replace")
        c.close()
        ms = (time.perf_counter() - t0) * 1000.0
        status = None
        try:
            status = json.loads(resp).get("status")
        except Exception:
            pass
        return {"ms": round(ms, 1), "timeout": False, "crash": False, "status": status,
                "bytes": len(body), "resp": resp[:200]}
    except (socket.timeout, TimeoutError):
        ms = (time.perf_counter() - t0) * 1000.0
        return {"ms": round(max(ms, HTTP_TIMEOUT_MS), 1), "timeout": True, "crash": False,
                "status": "timeout", "bytes": len(body), "resp": None}
    except (http.client.RemoteDisconnected, ConnectionResetError, ConnectionRefusedError, OSError) as e:
        ms = (time.perf_counter() - t0) * 1000.0
        return {"ms": round(ms, 1), "timeout": False, "crash": True, "status": "crash",
                "bytes": len(body), "resp": None, "error": str(e)}


def is_dos(r: dict) -> bool:
    return bool(r.get("timeout") or r.get("crash") or r["ms"] > T_SLOW)


def is_bounded_fast(r: dict) -> bool:
    return (not is_dos(r)) and r["ms"] < T_FAST and r.get("status") in ("parsed", "limited")


def measure_profile(prof: str) -> dict:
    """Measure each payload against a FRESH server. A synchronous entity-expansion permanently pins
    the CPU (or crashes the container via mem exhaustion), so we restart (kill + up -d -> brand-new
    ruby process) before every probe to guarantee a clean baseline."""
    port = PORTS[prof]
    results = {}
    try:
        for kind in ("benign", "original", "residual"):
            run(COMPOSE + ["--profile", prof, "kill", prof], check=False,
                capture_output=True, text=True)
            run(COMPOSE + ["--profile", prof, "rm", "-f", prof], check=False,
                capture_output=True, text=True)
            time.sleep(2)
            run(COMPOSE + ["--profile", prof, "up", "-d", "--force-recreate"], check=True,
                capture_output=True, text=True)
            if not wait_health(port, timeout_s=120.0):
                raise RuntimeError(f"{prof}: /health never came up on :{port}")
            r = probe(port, kind)
            results[kind] = r
            print(f"[{prof}] {kind:9s} bytes={r['bytes']:>4} -> {r['ms']:>8}ms "
                  f"status={r.get('status')} timeout={r.get('timeout')} crash={r.get('crash')} "
                  f"dos={is_dos(r)}", flush=True)
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

    def res(v, kind):
        return versions[v]["results"][kind]

    matrix = {v: {k: {"ms": res(v, k)["ms"], "status": res(v, k).get("status"),
                      "dos": is_dos(res(v, k))}
                  for k in ("benign", "original", "residual")}
              for v in versions}

    booleans = {
        "original_dos_on_v0": is_dos(res("v0", "original")),
        "original_bounded_on_v1": is_bounded_fast(res("v1", "original")),
        "residual_dos_on_v1": is_dos(res("v1", "residual")),
        "residual_bounded_on_v2": is_bounded_fast(res("v2", "residual")),
        "benign_fast_on_all": all(is_bounded_fast(res(v, "benign")) for v in versions),
        "original_bounded_on_v2": is_bounded_fast(res("v2", "original")),
        "residual_dos_on_v0": is_dos(res("v0", "residual")),
    }
    booleans["passed"] = all(booleans.values())

    report = {
        "case": "ruby-rexml-cve-2014-8090",
        "oracle_variant": "dos-threshold",
        "run_mode": "real-app-http",
        "external_http_trigger": True,
        "runs_real_software": True,
        "thresholds": {"T_FAST_ms": T_FAST, "T_SLOW_ms": T_SLOW, "http_timeout_ms": HTTP_TIMEOUT_MS},
        "latency_matrix": matrix,
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
