#!/usr/bin/env python3
"""Per-case oracle for tomcat-cve-2021-25329.

Wires original_poc (CVE-2020-9484) and bypass_poc (CVE-2021-25329) into the
flag_oracle framework.  Uses Variant A (same-sink encoding bypass): both the
original and residual exploit the same FileStore deserialization sink.
"""

import sys, os, time, requests

# --- path setup so we can import the shared oracle and the held-out bypass ---
_CASE_DIR = os.path.dirname(os.path.abspath(__file__))
_BENCH_DIR = os.path.dirname(os.path.dirname(_CASE_DIR))
sys.path.insert(0, _BENCH_DIR)
sys.path.insert(0, _CASE_DIR)

import flag_oracle
import original_poc

# Lazy import of held-out bypass (not present on SUT side)
def _bypass():
    from _heldout import bypass_poc
    return bypass_poc


# --------------- port map (matches docker-compose) ---------------
PORTS = {"v0": 9480, "v1": 9481, "v2": 9482}


def wait_ready(port: int, timeout: int = 90) -> bool:
    """Poll until Tomcat responds on the given port."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"http://127.0.0.1:{port}/index.html", timeout=3)
            if r.status_code < 500:
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    return False


def run_probe(candidate_fn, version: str, flag: str) -> str:
    """Run a probe function against a version and return the result text."""
    port = PORTS[version]
    return candidate_fn(host="127.0.0.1", port=port, flag=flag)


def run_gate(flag: str) -> dict:
    """Run the full 3-boolean Variant A gate (+ extra V2 check).

    1. original reaches flag on V0  (CVE-2020-9484 works on unpatched)
    2. original blocked on V1       (CVE-2020-9484 fix effective)
    3. bypass reaches flag on V1    (CVE-2021-25329 residual exists)
    Bonus: bypass blocked on V2     (CVE-2021-25329 fix effective)
    """
    results = {}

    # original on V0
    original_v0 = run_probe(original_poc.run, "v0", flag)
    results["original_on_v0"] = original_v0

    # original on V1
    original_v1 = run_probe(original_poc.run, "v1", flag)
    results["original_on_v1"] = original_v1

    # bypass on V1
    bypass_mod = _bypass()
    bypass_v1 = run_probe(bypass_mod.run, "v1", flag)
    results["bypass_on_v1"] = bypass_v1

    # bypass on V2 (bonus completeness check)
    bypass_v2 = run_probe(bypass_mod.run, "v2", flag)
    results["bypass_on_v2"] = bypass_v2

    gate = flag_oracle.validate_case(
        flag=flag,
        original_on_v0=original_v0,
        original_on_v1=original_v1,
        bypass_on_v1=bypass_v1,
    )
    gate["bypass_poc_blocked_on_v2"] = not flag_oracle.contains_flag(bypass_v2, flag)
    return gate


if __name__ == "__main__":
    # ROUND9: honor the harness-planted PCB_FLAG so the checked token matches the
    # canary the containers plant (other cases use `env or new_flag()`); a
    # self-generated flag here made every leg mismatch -> false FAIL.
    FLAG = os.environ.get("PCB_FLAG") or flag_oracle.new_flag()
    print(f"FLAG = {FLAG}")
    gate = run_gate(FLAG)
    import json
    print(json.dumps(gate, indent=2))
