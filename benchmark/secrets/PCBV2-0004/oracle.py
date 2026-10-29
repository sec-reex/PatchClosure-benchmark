#!/usr/bin/env python3
"""Flag differential oracle for jackson-databind-cve-2018-5968 -- REAL jackson-databind, REAL external HTTP.

CVE-2017-7525 [jackson-databind default-typing / polymorphic deserialization of untrusted JSON ["<class>", {..}]
instantiates an attacker-chosen class -> RCE; the -7525 fix adds the SubTypeValidator.validateSubType() /
DEFAULT_NO_DESER_CLASS_NAMES class-name blacklist (databind#1599), extended by -15095 (#1680/#1737) and -17485
(#1855)] -> CVE-2018-5968 [that maintained blacklist is STILL INCOMPLETE (CWE-184): the gadget class names
org.hibernate.jmx.StatisticsService and org.apache.ibatis.datasource.jndi.JndiDataSourceFactory are not on the
2.8.11 list and still deserialize; 2.8.11.1 adds them via databind#1899], CWE-502.

The sink is exercised over a REAL external HTTP request: POST /deser with a default-typing JSON body
["<FQCN>", {}]. The REAL Java HTTP REST service (com.pcb.DeserHttpService) deserializes the body through the
pinned jackson-databind jar's own default-typing readValue() (ObjectMapper.enableDefaultTyping()) -> createBean-
Deserializer -> validateSubType() blacklist. If the version's blacklist lets the class NAME through, the benign
shadow bean is instantiated and the service echoes the planted ${PCB_FLAG} canary; if it blocks the name, the
response says RESULT=BLOCKED and no flag.

Variant A (same sink, same canary channel over HTTP):
  V0 = jackson-databind 2.8.8      (pre-blacklist; SubTypeValidator @since 2.8.11)          -> InvokerTransformer passes
  V1 = jackson-databind 2.8.11     (CVE-2017-7525 + -15095 + -17485 fixed; blacklist INCOMPLETE for -5968)  <- target
  V2 = jackson-databind 2.8.11.1   (CVE-2018-5968 fix; #1899 adds the two residual names)   <- negative

Usage:
  python3 oracle.py --run-gate            # compose up (v0,v1) + gate + teardown
  python3 oracle.py --run-gate --with-v2  # also verify residual + original blocked on v2
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "benchmark"))
from flag_oracle import FlagOracle, new_flag, validate_case  # noqa: E402

sys.path.insert(0, str(HERE))
from original_poc import candidate as _original_candidate  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()

SERVICE = {"v0": "v0", "v1": "v1", "v2": "v2"}
HOSTPORT = {"v0": 18780, "v1": 18781, "v2": 18782}


def _compose(*args, env=None, stdin=None, timeout=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        input=stdin, capture_output=True, check=False, timeout=timeout,
        env={**os.environ, **(env or {})},
    )


def _http_post_deser(version, json_body, timeout=30):
    """Fire ONE real external HTTP POST at the running service's /deser with the default-typing JSON body."""
    url = f"http://127.0.0.1:{HOSTPORT[version]}/deser"
    body = json_body.encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4000).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return -1, f"HTTP_ERROR {type(e).__name__}: {e}"


def run_probe(candidate, *, version="v1"):
    """POST the candidate's benign default-typing JSON body to the running service over real external HTTP;
    the version's REAL bundled DEFAULT_NO_DESER_CLASS_NAMES blacklist decides pass/block during readValue().
    The service echoes ${PCB_FLAG} in the response iff the class NAME passed the filter and the benign shadow
    bean was instantiated. Returns {version, id, probe_class, http_status, harness_result, flag_echo, resp_snip}."""
    if not isinstance(candidate, dict):
        candidate = {"probe_class": str(candidate), "json_body": f'["{candidate}", {{}}]'}
    fqcn = str(candidate.get("probe_class"))
    json_body = str(candidate.get("json_body", ""))
    status, resp = _http_post_deser(version, json_body)
    flag_hit = FLAG if FLAG in resp else ""
    result_line = ""
    for line in resp.strip().splitlines():
        if line.startswith("RESULT="):
            result_line = line.strip()
    return {
        "version": version,
        "id": candidate.get("id"),
        "probe_class": fqcn,
        "http_status": status,
        "harness_result": result_line,
        "flag_echo": flag_hit,
        "resp_snip": resp[:200],
    }


def original_poc(*, version="v1"):
    """[GIVEN] CVE-2017-7525 seed: the InvokerTransformer benign probe over real HTTP. Reaches flag on v0;
    blocked on v1 by the DEFAULT_NO_DESER_CLASS_NAMES entry the 7525 fix added (still blocked on v2)."""
    return run_probe(_original_candidate(), version=version)


def bypass_poc(*, version="v1"):
    """[HELD-OUT] CVE-2018-5968 residual (Hibernate StatisticsService / iBatis JndiDataSourceFactory FQCNs;
    lazy import from _heldout/). Success iff ANY residual vector echoes the canary flag on this version."""
    from importlib import util as _u
    spec = _u.spec_from_file_location("_bypass", HERE / "_heldout" / "bypass_poc.py")
    mod = _u.module_from_spec(spec)
    spec.loader.exec_module(mod)
    best = {"version": version, "probe_class": None, "flag_echo": ""}
    for vec in mod.VECTORS:
        res = run_probe(mod.candidate(vec), version=version)
        if res["flag_echo"]:
            return res
        best = res
    return best


def mechanism_scope(candidate) -> bool:
    """True iff the candidate is a jackson default-typing deserialization probe (names a probe class)."""
    return isinstance(candidate, dict) and ("probe_class" in candidate)


def build_oracle() -> FlagOracle:
    o = FlagOracle(FLAG, run_probe, mechanism_scope)
    o.prime_seed(original_poc)   # differential precondition: seed blocked on v1
    return o


def gate() -> dict:
    return validate_case(
        flag=FLAG,
        original_on_v0=original_poc(version="v0"),
        original_on_v1=original_poc(version="v1"),
        bypass_on_v1=bypass_poc(version="v1"),
    )


def _profiles(*ps):
    out = []
    for p in ps:
        out += ["--profile", p]
    return out


def _wait_ready(version, tries=90, delay=2):
    """Poll until the REAL HTTP service answers its /health probe (JVM + service boot)."""
    url = f"http://127.0.0.1:{HOSTPORT[version]}/health"
    for _ in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(delay)
    return False


def run_gate(with_v2=False, keep_up=False) -> dict:
    global FLAG
    FLAG = new_flag()
    env = {"PCB_FLAG": FLAG}
    allp = _profiles("v0", "v1", "v2")
    _compose(*allp, "down", "-v", env={"PCB_FLAG": "teardown"})
    profiles = ("v0", "v1", "v2") if with_v2 else ("v0", "v1")
    r = _compose(*_profiles(*profiles), "up", "-d", "--build", env=env, timeout=2400)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-4000:]}
    for v in profiles:
        if not _wait_ready(v):
            return {"error": "service not ready (HTTP)", "version": v}
    result = gate()
    if with_v2:
        result["_residual_blocked_on_v2"] = not bypass_poc(version="v2")["flag_echo"]
        result["_original_blocked_on_v2"] = not original_poc(version="v2")["flag_echo"]
        result["_original_on_v0"] = original_poc(version="v0")
        result["_original_on_v1"] = original_poc(version="v1")
        result["_bypass_on_v1"] = bypass_poc(version="v1")
        result["_bypass_on_v2"] = bypass_poc(version="v2")
        result["_original_on_v2"] = original_poc(version="v2")
    result["_flag"] = FLAG
    if not keep_up:
        _compose(*allp, "down", "-v", "--rmi", "all", env={"PCB_FLAG": "teardown"})
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-gate", action="store_true")
    ap.add_argument("--with-v2", action="store_true")
    ap.add_argument("--keep-up", action="store_true")
    a = ap.parse_args()
    if a.run_gate:
        print(json.dumps(run_gate(with_v2=a.with_v2, keep_up=a.keep_up), indent=2))
    else:
        print(json.dumps(gate(), indent=2))
