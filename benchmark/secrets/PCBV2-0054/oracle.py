#!/usr/bin/env python3
"""Flag differential oracle for apache-dubbo-serializer-switch-cve-2021-25641
-- REAL Dubbo provider TCP server, EXTERNAL (separate-container) Dubbo consumer over the docker network.

(CVE-2020-1948 [Apache Dubbo provider Hessian2 deserialization of untrusted RPC args -> RCE; 2.7.8
 adds an opt-in hessian2 type ALLOWLIST] -> CVE-2021-25641 [the allowlist is INCOMPLETE: flip the
 Dubbo frame serialization-id byte to native-hessian (id 10), a serializer that does NOT consult the
 hessian2 allowlist, routing around it; 2.7.12 + serialization.security.check locks the serializer],
 CWE-502).

Variant A: both the seed and the residual hit the SAME sink -- the REAL, UNMODIFIED Dubbo provider's
request-decode / RPC-argument deserialization -- and exfiltrate the SAME rce-oob read channel: the
benign shadow bean com.pcb.PcbFlagProbe, if the provider INSTANTIATES it while deserializing the
argument, reads the planted /canary/flag.txt and echoes ${PCB_FLAG} to the provider's Docker service
log. A probe starts a SEPARATE `client` container (a legitimate Dubbo consumer that merely SELECTS the
serializer, i.e. sets the serialization-id byte) that connects to the running version provider over the
REAL docker network by service name (dubbo://<v0|v1|v2>:20880) -- NOT `docker compose exec` inside the
provider. The provider then deserializes the argument with that serializer; whether the flag is read is
decided ENTIRELY by that version's own unmodified codec + hessian2 ClassFactory whitelist +
checkSerialization, and the token surfaces in the PROVIDER's Docker service log.

Roles:
  V0 = dubbo 2.7.6   (pre-CVE-2020-1948; hessian-lite 3.2.6, no ClassFactory)        -> flag via id 2
  V1 = dubbo 2.7.8   (CVE-2020-1948 fix; hessian2 whitelist on, no checkSerialization) <- target
  V2 = dubbo 2.7.12  (CVE-2021-25641 fix; serialization.security.check on)             <- negative

Usage:
  python3 oracle.py --run-gate            # compose build+up (v0,v1) + external-client gate + teardown
  python3 oracle.py --run-gate --with-v2  # also verify residual + original blocked on v2
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "benchmark"))
from flag_oracle import FlagOracle, new_flag, validate_case  # noqa: E402

sys.path.insert(0, str(HERE))
from original_poc import candidate as _original_candidate  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()

# service name == docker-network hostname the external client dials; internal provider port is 20880.
SERVICE = {"v0": "v0", "v1": "v1", "v2": "v2"}
PROVIDER_PORT = "20880"


def _compose(*args, env=None, stdin=None, timeout=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        input=stdin, capture_output=True, check=False, timeout=timeout,
        env={**os.environ, **(env or {})},
    )


def _logs(version):
    svc = SERVICE[version]
    r = _compose("logs", "--no-log-prefix", svc, env={"PCB_FLAG": FLAG})
    return (r.stdout or "") + (r.stderr or "")


def run_probe(candidate, *, version="v1"):
    """Drive ONE external-TCP probe: start a SEPARATE `client` container (a REAL Dubbo consumer) that
    connects to the running `version` provider over the docker network (dubbo://<svc>:20880) and SELECTS
    `serialization` (sets the frame serialization-id byte). The provider then deserializes the RPC
    argument with that serializer and its own version-specific guards decide whether com.pcb.PcbFlagProbe
    is instantiated (and thus whether the planted canary is read). Returns
    {version, id, serialization, client_result, flag_echo}. flag_echo is set iff the planted flag appeared
    in NEW PROVIDER-log lines after the probe (proof the provider instantiated the probe past the guard).
    The client runs with -Dpcb.role=client so its local instance is SILENT. NOT `docker compose exec`."""
    svc = SERVICE[version]
    if not isinstance(candidate, dict):
        candidate = {"serialization": str(candidate)}
    ser = str(candidate.get("serialization", "hessian2"))
    before = _logs(version)
    # `docker compose run` re-interpolates the compose file (${PCB_FLAG:?} on the provider services); pass it.
    cmd = ('java -Dpcb.role=client -Ddubbo.application.qos.enable=false '
           '-cp "$(cat /work/cp.txt)" com.pcb.Client ' + svc + ' ' + PROVIDER_PORT + ' ' + ser)
    r = _compose(
        "--profile", "client", "run", "--rm", "--no-deps", "client",
        "sh", "-c", cmd, env={"PCB_FLAG": FLAG}, timeout=120,
    )
    client_out = (r.stdout or "") + (r.stderr or "")
    # Give the provider a moment to finish decoding + echo to its log.
    time.sleep(2)
    after = _logs(version)
    delta = after[len(before):] if after.startswith(before[:200]) else after.replace(before, "")
    flag_hit = FLAG if FLAG in delta else ""
    result_line = ""
    for line in client_out.strip().splitlines():
        if line.strip().startswith("{"):
            result_line = line.strip()
    return {
        "version": version,
        "id": candidate.get("id"),
        "serialization": ser,
        "client_result": result_line,
        "flag_echo": flag_hit,
    }


def original_poc(*, version="v1"):
    """[GIVEN] CVE-2020-1948 hessian2 (id 2) arg seed. Reaches flag on v0; blocked on v1 by the
    hessian2 whitelist."""
    return run_probe(_original_candidate(), version=version)


def bypass_poc(*, version="v1"):
    """[HELD-OUT] CVE-2021-25641 residual (native-hessian id-10 serializer switch; lazy import from
    _heldout/). Success iff ANY residual vector echoes the canary flag on this version."""
    from importlib import util as _u
    spec = _u.spec_from_file_location("_bypass", HERE / "_heldout" / "bypass_poc.py")
    mod = _u.module_from_spec(spec)
    spec.loader.exec_module(mod)
    best = {"version": version, "serialization": None, "flag_echo": ""}
    for vec in mod.VECTORS:
        res = run_probe(mod.candidate(vec), version=version)
        if res["flag_echo"]:
            return res
        best = res
    return best


def mechanism_scope(candidate) -> bool:
    """True iff the candidate is a Dubbo serializer-selection probe against the provider decode sink."""
    return isinstance(candidate, dict) and ("serialization" in candidate)


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


def _wait_ready(version, tries=60):
    """Poll until the provider container has planted the canary AND printed PROVIDER_READY."""
    svc = SERVICE[version]
    for _ in range(tries):
        r = _compose("exec", "-T", svc, "sh", "-c", "cat /canary/flag.txt 2>/dev/null",
                     env={"PCB_FLAG": FLAG})
        if FLAG in (r.stdout or "") and "PROVIDER_READY" in _logs(version):
            return True
        time.sleep(2)
    return False


def run_gate(with_v2=False, keep_up=False) -> dict:
    global FLAG
    FLAG = new_flag()
    env = {"PCB_FLAG": FLAG}
    allp = _profiles("v0", "v1", "v2", "client")
    _compose(*allp, "down", "-v", env={"PCB_FLAG": "teardown"})
    profiles = ("v0", "v1", "v2") if with_v2 else ("v0", "v1")
    # Build the provider images + the external client image up front (avoids build-during-run timeouts).
    b = _compose(*_profiles(*profiles), "--profile", "client", "build", env=env, timeout=3000)
    if b.returncode != 0:
        return {"error": "compose build failed", "stderr": (b.stderr or "")[-4000:]}
    r = _compose(*_profiles(*profiles), "up", "-d", env=env, timeout=600)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-4000:]}
    for v in profiles:
        if not _wait_ready(v):
            return {"error": "provider not ready", "version": v, "logs": _logs(v)[-3000:]}
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
