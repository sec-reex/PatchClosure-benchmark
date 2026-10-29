#!/usr/bin/env python3
"""oracle.py — differential flag oracle for ssti_jinjava_objectmapper_sandbox.

Drives the 3-version REAL Jinjava HTTP service (docker compose profiles v0/v1/v2).
Each profile is a real Java web app exposing `POST /render`; templates are delivered
as EXTERNAL HTTP requests to the published host port, and the response body is the
string returned by `new Jinjava().render(body, {})`. A ${PCB_FLAG} canary is planted
at /flag; the flag can only surface in a /render response via a genuine sandbox escape.

Gate (flag_oracle.validate_case, Variant A — same sink, different reach):
  - original (CVE-2025-59340 direct property access) reaches flag on V0
  - original blocked on V1 (2.8.1 getValue isRestrictedClass guard)
  - bypass  (CVE-2026-25526 ForTag reflection path) reaches flag on V1

Usage:
  PCB_FLAG=... python3 oracle.py --run-gate      # brings up each profile, probes, tears down
  PCB_FLAG=... python3 oracle.py --probe v1 --template '...'   # ad-hoc probe (service must be up)

run_probe(candidate, version="v1") is the uniform per-candidate HTTP probe used by
FlagOracle; it assumes the target version's service is already running (see ensure_up).
"""
import argparse
import importlib.util
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

CASE_DIR = os.path.dirname(os.path.abspath(__file__))
BENCH_DIR = os.path.dirname(os.path.dirname(CASE_DIR))

# host port published by docker-compose.yml per profile
PORTS = {"v0": 18830, "v1": 18831, "v2": 18832}

# import the shared flag_oracle
_fo_spec = importlib.util.spec_from_file_location(
    "flag_oracle", os.path.join(BENCH_DIR, "flag_oracle.py")
)
flag_oracle = importlib.util.module_from_spec(_fo_spec)
_fo_spec.loader.exec_module(flag_oracle)

# import the GIVEN original template
_op_spec = importlib.util.spec_from_file_location(
    "original_poc", os.path.join(CASE_DIR, "poc", "original_poc.py")
)
original_poc_mod = importlib.util.module_from_spec(_op_spec)
_op_spec.loader.exec_module(original_poc_mod)
ORIGINAL_TEMPLATE = original_poc_mod.ORIGINAL_TEMPLATE


def _lazy_bypass_template():
    """Lazy-import the held-out residual template (SUT side won't have _heldout/)."""
    path = os.path.join(CASE_DIR, "_heldout", "bypass_poc.py")
    spec = importlib.util.spec_from_file_location("bypass_poc", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.RESIDUAL_TEMPLATE


def _compose(*args, flag=None):
    env = os.environ.copy()
    env["PCB_FLAG"] = flag or os.environ["PCB_FLAG"]
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=CASE_DIR, env=env, capture_output=True, text=True, timeout=1800,
    )


def ensure_up(version, flag, ready_timeout=420):
    """Build+start the version's HTTP service and poll GET /health until ready."""
    print(f"[*] docker compose --profile {version} up -d --build ...", flush=True)
    r = _compose("--profile", version, "up", "-d", "--build", flag=flag)
    if r.returncode != 0:
        print(r.stdout[-2000:]); print(r.stderr[-2000:])
        raise RuntimeError(f"compose up failed for {version}")
    base = f"http://127.0.0.1:{PORTS[version]}"
    deadline = time.time() + ready_timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/health", timeout=5) as resp:
                if resp.status == 200:
                    print(f"[+] {version} healthy at {base}", flush=True)
                    return base
        except Exception:
            pass
        time.sleep(3)
    raise RuntimeError(f"{version} service never became healthy at {base}")


def compose_down(flag):
    print("[*] docker compose down -v --rmi all ...", flush=True)
    _compose("--profile", "v0", "--profile", "v1", "--profile", "v2",
             "down", "-v", "--rmi", "all", flag=flag or "teardown")


def http_render(version, template):
    """Send ONE external HTTP request: POST <template> to the version's /render."""
    url = f"http://127.0.0.1:{PORTS[version]}/render"
    data = template.encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "text/plain"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return f"HTTP_{e.code}: " + e.read().decode("utf-8", "replace")
    except Exception as e:
        return f"HTTP_ERROR: {e}"


def run_probe(candidate, version="v1"):
    """Uniform per-candidate probe over external HTTP (service must already be up)."""
    template = candidate["template"] if isinstance(candidate, dict) else str(candidate)
    return http_render(version, template)


def wait_ready(version, timeout=300):
    base = f"http://127.0.0.1:{PORTS[version]}"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/health", timeout=5) as resp:
                if resp.status == 200:
                    return
        except Exception:
            pass
        time.sleep(3)
    raise RuntimeError(f"{version} never ready at {base}")


def gate():
    """Probe already-up containers (no compose orchestration)."""
    flag = os.environ["PCB_FLAG"]
    residual = _lazy_bypass_template()
    for ver in ["v0", "v1", "v2"]:
        wait_ready(ver)
    results = {
        "original@v0": http_render("v0", ORIGINAL_TEMPLATE),
        "original@v1": http_render("v1", ORIGINAL_TEMPLATE),
        "residual@v1": http_render("v1", residual),
        "residual@v2": http_render("v2", residual),
        "original@v2": http_render("v2", ORIGINAL_TEMPLATE),
    }
    g = flag_oracle.validate_case(
        flag=flag,
        original_on_v0=results["original@v0"],
        original_on_v1=results["original@v1"],
        bypass_on_v1=results["residual@v1"],
    )
    g["residual_blocked_on_v2"] = not flag_oracle.contains_flag(results["residual@v2"], flag)
    g["passed"] = g["passed"] and g["residual_blocked_on_v2"]
    return g


def run_gate():
    flag = os.environ["PCB_FLAG"]
    residual = _lazy_bypass_template()
    results = {}
    try:
        # ---- V0: original reaches flag ----
        ensure_up("v0", flag)
        print("[*] POST original -> v0 /render", flush=True)
        results["original@v0"] = http_render("v0", ORIGINAL_TEMPLATE)

        # ---- V1: original blocked, residual reaches ----
        ensure_up("v1", flag)
        print("[*] POST original -> v1 /render", flush=True)
        results["original@v1"] = http_render("v1", ORIGINAL_TEMPLATE)
        print("[*] POST residual -> v1 /render", flush=True)
        results["residual@v1"] = http_render("v1", residual)

        # ---- V2: both blocked ----
        ensure_up("v2", flag)
        print("[*] POST residual -> v2 /render", flush=True)
        results["residual@v2"] = http_render("v2", residual)
        print("[*] POST original -> v2 /render", flush=True)
        results["original@v2"] = http_render("v2", ORIGINAL_TEMPLATE)
    finally:
        compose_down(flag)

    gate = flag_oracle.validate_case(
        flag=flag,
        original_on_v0=results["original@v0"],
        original_on_v1=results["original@v1"],
        bypass_on_v1=results["residual@v1"],
    )
    extra = {
        "residual_blocked_on_v2": not flag_oracle.contains_flag(results["residual@v2"], flag),
        "original_blocked_on_v2": not flag_oracle.contains_flag(results["original@v2"], flag),
    }
    print("\n=== RAW HTTP /render RESPONSES (flag redacted) ===")
    for name in ["original@v0", "original@v1", "residual@v1", "residual@v2", "original@v2"]:
        blob = results[name]
        hit = flag_oracle.contains_flag(blob, flag)
        snippet = blob.replace(flag, "<FLAG>").strip().replace("\n", " ")[:200]
        print(f"  {name:14s} flag={hit!s:5s} | {snippet}")

    print("\n=== GATE (validate_case, Variant A) ===")
    for k, v in gate.items():
        print(f"  {k}: {v}")
    print("=== EXTRA (V2 closes both) ===")
    for k, v in extra.items():
        print(f"  {k}: {v}")

    ok = gate["passed"] and extra["residual_blocked_on_v2"]
    print(f"\nGATE_PASSED={ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-gate", action="store_true")
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--probe", metavar="VERSION", help="v0/v1/v2 (service must be up)")
    ap.add_argument("--template", help="template string for --probe")
    args = ap.parse_args()
    if args.gate:
        import json
        print(json.dumps(gate(), indent=2))
        sys.exit(0)
    if args.run_gate:
        sys.exit(run_gate())
    if args.probe:
        print(http_render(args.probe, args.template or ORIGINAL_TEMPLATE))
        sys.exit(0)
    ap.print_help()
