#!/usr/bin/env python3
"""Flag differential oracle for deser_mina_objser -- REAL MINA TCP server, EXTERNAL TCP client.

(CVE-2024-52046 [Apache MINA ObjectSerializationDecoder / AbstractIoBuffer.getObject() unbounded Java
 deserialization -> RCE; fix ADDS the acceptMatchers class allowlist, enforced ONLY in resolveClass()'s
 non-null (type-1) branch] -> CVE-2026-42779 [type-0/null-clazz descriptor bypass: a 0x00 class descriptor
 routes to resolveClass()'s null-clazz branch, which calls Class.forName WITHOUT the allowlist; the
 incomplete-fix follow-up to CVE-2026-41635, whose fix was never backported to mina-core 2.2.x], CWE-502).

Apache MINA is a NETWORK framework -- its real usage is a TCP server. Each version service runs a REAL
MINA NioSocketAcceptor + ProtocolCodecFilter(ObjectSerializationCodecFactory) with the acceptMatchers
allowlist accepting ONLY PcbExpected. A SEPARATE `client` container (Client.java) connects over the docker
network and writes a length-prefixed MINA serialized stream; the server's REAL, unmodified doDecode ->
setMatchers(acceptMatchers) -> getObject() decides whether PcbSeed is reconstructed for the given wire
descriptor type. This is a genuine EXTERNAL network trigger (real TCP, real separate process), the way
MINA is actually used. Nothing is deserialized in-process by a test harness.

Variant A: both the seed and the residual hit the SAME sink -- the running MINA server's getObject() --
with the SAME canary class (PcbSeed) and the SAME rce-oob channel (/canary/flag.txt read in readObject,
echoed back over TCP). The ONLY difference is the MINA WIRE ENCODING of the class descriptor: the seed
uses a normal type-1 descriptor (allowlist-checked in resolveClass's non-null branch), the residual forces
a type-0/null-clazz descriptor (routed to the unguarded null-clazz branch).

Roles:
  V0 = mina-core 2.2.3  (pre-CVE-2024-52046; NO allowlist -> seed fully deserializes -> flag)
  V1 = mina-core 2.2.6  (CVE-2024-52046 allowlist present; type-0/null-clazz branch unguarded)  <- target
  V2 = mina-core 2.2.7  (CVE-2026-42779 patched; allowlist applied before Class.forName in both branches)  <- negative

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

# service name == docker-network hostname the external client dials; internal server port is 9009.
SERVICE = {"v0": "v0", "v1": "v1", "v2": "v2"}
SERVER_PORT = "9009"

# Run the EXTERNAL attacker client in its own throwaway container, connecting over the docker network.
CLIENT_CMD = 'java -cp "$(cat /work/cp.txt)" Client'


def _compose(*args, env=None, stdin=None, timeout=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        input=stdin, capture_output=True, check=False, timeout=timeout,
        env={**os.environ, **(env or {})},
    )


def run_probe(candidate, *, version="v1"):
    """Drive ONE external-TCP probe: start a separate `client` container that connects to the running
    `version` MINA server over the docker network and sends the crafted MINA stream (mode=type1/type0/
    expected). The server's REAL getObject() + that version's allowlist ordering decide whether PcbSeed's
    readObject reads the planted canary; if so the server echoes the token back over TCP and it appears in
    the client's received bytes. Returns {version, mode, deserialized_hint, flag_echo, raw}."""
    svc = SERVICE[version]
    if not isinstance(candidate, dict):
        candidate = {"mode": str(candidate)}
    mode = candidate.get("mode", "type1")
    # `docker compose run` re-interpolates the compose file (${PCB_FLAG:?} on the server services); pass it.
    r = _compose(
        "--profile", "client", "run", "--rm", "--no-deps", "client",
        "sh", "-c", f"{CLIENT_CMD} {svc} {SERVER_PORT} {mode}",
        env={"PCB_FLAG": FLAG}, timeout=120,
    )
    out = (r.stdout or "") + (r.stderr or "")
    flag_hit = FLAG if FLAG in out else ""
    resp = ""
    for line in out.splitlines():
        if line.startswith("CLIENT_RESP="):
            resp = line[len("CLIENT_RESP="):]
            break
    return {
        "version": version,
        "id": candidate.get("id"),
        "mode": mode,
        "resp": resp,
        "flag_echo": flag_hit,
        "raw": out[-600:],
    }


def original_poc(*, version="v1"):
    """[GIVEN] CVE-2024-52046 unbounded-deserialization seed: PcbSeed as a NORMAL MINA type-1 payload,
    sent by the external TCP client. Reaches flag on v0; blocked on v1 by the acceptMatchers allowlist
    (resolveClass non-null branch)."""
    return run_probe(_original_candidate(), version=version)


def bypass_poc(*, version="v1"):
    """[HELD-OUT] CVE-2026-42779 type-0/null-clazz-descriptor residual (lazy import from _heldout/).
    Success iff ANY residual vector echoes the canary flag on this version."""
    from importlib import util as _u
    spec = _u.spec_from_file_location("_bypass", HERE / "_heldout" / "bypass_poc.py")
    mod = _u.module_from_spec(spec)
    spec.loader.exec_module(mod)
    best = {"version": version, "mode": None, "flag_echo": ""}
    for vec in mod.VECTORS:
        res = run_probe(mod.candidate(vec), version=version)
        if res["flag_echo"]:
            return res
        best = res
    return best


def mechanism_scope(candidate) -> bool:
    """True iff the candidate drives the MINA deserialization sink -- it sends a serialized-object mode
    (type1/type0/expected) to the running MINA server, i.e. exercises the same allowlist+sink."""
    return isinstance(candidate, dict) and str(candidate.get("mode", "")) in ("type1", "type0", "expected")


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
    """Poll until the version's MINA TCP server has bound its port (prints PCB_SERVER_LISTENING) AND the
    canary file is planted."""
    svc = SERVICE[version]
    for _ in range(tries):
        logs = _compose("logs", "--no-color", svc, env={"PCB_FLAG": FLAG})
        canary = _compose("exec", "-T", svc, "sh", "-c", "cat /canary/flag.txt 2>/dev/null",
                          env={"PCB_FLAG": FLAG})
        if "PCB_SERVER_LISTENING" in (logs.stdout or "") and FLAG in (canary.stdout or ""):
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
    # Build servers + the external client image up front (avoids build-during-run timeouts).
    b = _compose(*_profiles(*profiles), "--profile", "client", "build", env=env, timeout=3000)
    if b.returncode != 0:
        return {"error": "compose build failed", "stderr": (b.stderr or "")[-4000:]}
    r = _compose(*_profiles(*profiles), "up", "-d", env=env, timeout=600)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": (r.stderr or "")[-4000:]}
    for v in profiles:
        if not _wait_ready(v):
            return {"error": "server not ready", "version": v,
                    "logs": (_compose("logs", "--no-color", SERVICE[v]).stdout or "")[-2000:]}
    result = gate()
    # Control: the legit allowlisted class passes the guard on v1 (proves the allowlist is live, not deny-all).
    result["_expected_on_v1"] = run_probe({"id": "legit", "mode": "expected"}, version="v1")
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
