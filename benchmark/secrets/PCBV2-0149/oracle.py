#!/usr/bin/env python3
"""Flag differential oracle for netty-cve-2020-7238
(CVE-2019-16869 -> CVE-2020-7238, io.netty netty-codec-http HttpObjectDecoder request
framing, CWE-444 HTTP request smuggling).

Variant A: seed and residual hit the SAME sink (HttpObjectDecoder request-framing in
one tiny unmodified Netty origin server) and the SAME flag channel -- a pipelined
`GET /flag` smuggled sub-request that reaches the internal ${PCB_FLAG} route iff this
version's decoder ACCEPTS the malformed front-request framing. A probe ships a raw byte
buffer over a socket; the version's own HttpObjectDecoder decides acceptance. Nothing in
Netty is modified.

Roles:
  V0 = netty 4.1.41.Final  (pre-fix; splitHeader breaks name loop at SP -> seed reaches)
  V1 = netty 4.1.43.Final  (CVE-2019-16869 fix; SP-in-name rejected; CL+TE still accepted) <- incomplete
  V2 = netty 4.1.44.Final  (CVE-2020-7238 fix; CL+TE rejected -- negative)

Usage:
  python3 oracle.py --run-gate            # compose up (v0,v1) + gate + teardown
  python3 oracle.py --run-gate --with-v2  # also verify residual/seed blocked on v2
"""
from __future__ import annotations

import argparse
import json
import os
import socket
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

ADDR = {
    "v0": ("127.0.0.1", 39760),
    "v1": ("127.0.0.1", 39761),
    "v2": ("127.0.0.1", 39762),
}


def _send_raw(addr, raw: bytes, timeout: float = 6.0) -> str:
    """Open a socket to `addr`, send `raw` bytes, read the full response stream until
    the server closes (Connection: close on the smuggled request) or timeout."""
    host, port = addr
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return f"<connect-error: {e}>"
    s.settimeout(timeout)
    buf = b""
    try:
        s.sendall(raw)
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break
    except OSError:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass
    return buf.decode("latin-1")


def run_probe(candidate, *, version="v1"):
    """Drive the version's real Netty HttpObjectDecoder with a raw crafted buffer.
    ${PCB_FLAG} appears in the response stream only if the smuggled `GET /flag` was
    processed, i.e. this version accepted the malformed front-request framing."""
    addr = ADDR.get(version)
    if addr is None:
        return {"version": version, "error": "no env for this version"}
    raw = candidate["raw"] if isinstance(candidate, dict) else bytes(candidate)
    body = _send_raw(addr, raw)
    return {
        "version": version,
        "id": candidate.get("id") if isinstance(candidate, dict) else None,
        "flag_seen": FLAG in body,
        "response": body[:400],
        "flag_echo": FLAG if FLAG in body else "",
    }


def original_poc(*, version="v1"):
    """[GIVEN] CVE-2019-16869 seed (Transfer-Encoding : chunked, SP before colon).
    Reaches flag on v0; blocked on v1."""
    return run_probe(_original_candidate(), version=version)


def bypass_poc(*, version="v1"):
    """[HELD-OUT] CVE-2020-7238 residual (Content-Length + Transfer-Encoding: chunked).
    Lazy-import from _heldout/ so a system run that never has _heldout/ can still import
    this module."""
    from importlib import util as _u

    spec = _u.spec_from_file_location("_bypass", HERE / "_heldout" / "bypass_poc.py")
    mod = _u.module_from_spec(spec)
    spec.loader.exec_module(mod)
    best = {"version": version, "flag_echo": ""}
    for vec in mod.VECTORS:
        res = run_probe(mod.candidate(vec), version=version)
        if res.get("flag_echo"):
            return res
        best = res
    return best


def mechanism_scope(candidate) -> bool:
    """True iff the candidate targets Netty's request-framing sink: a raw front request
    that obfuscates message length via Transfer-Encoding and/or Content-Length, then
    pipelines a smuggled request. Not an unrelated bug."""
    raw = candidate.get("raw") if isinstance(candidate, dict) else candidate
    if not raw:
        return False
    low = bytes(raw).lower()
    return b"transfer-encoding" in low and b"get /flag" in low


def build_oracle() -> FlagOracle:
    o = FlagOracle(FLAG, run_probe, mechanism_scope)
    o.prime_seed(original_poc)  # differential precondition: seed blocked on v1
    return o


def gate() -> dict:
    return validate_case(
        flag=FLAG,
        original_on_v0=original_poc(version="v0"),
        original_on_v1=original_poc(version="v1"),
        bypass_on_v1=bypass_poc(version="v1"),
    )


# --------------------------------------------------------------------------- docker plumbing
def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=str(HERE),
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, **(env or {})},
    )


def _profiles(*ps):
    out = []
    for p in ps:
        out += ["--profile", p]
    return out


def _wait_ready(version, tries=60):
    for _ in range(tries):
        body = _send_raw(ADDR[version], b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", timeout=4)
        if "ok" in body or "200" in body:
            return True
        time.sleep(2)
    return False


def run_gate(with_v2=False, keep_up=False) -> dict:
    global FLAG
    FLAG = new_flag()
    env = {"PCB_FLAG": FLAG}
    allp = _profiles("v0", "v1", "v2")
    _compose(*allp, "down", "-v", env={"PCB_FLAG": "teardown"})
    profiles = ("v0", "v1", "v2") if with_v2 else ("v0", "v1")
    r = _compose(*_profiles(*profiles), "up", "-d", "--build", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-4000:]}
    for v in profiles:
        if not _wait_ready(v):
            return {"error": f"{v} never became ready", "logs": _compose("logs", v).stdout[-2000:]}
    time.sleep(1)
    result = gate()
    if with_v2:
        result["_seed_on_v0"] = original_poc(version="v0")
        result["_seed_on_v1"] = original_poc(version="v1")
        result["_seed_on_v2"] = original_poc(version="v2")
        result["_residual_on_v1"] = bypass_poc(version="v1")
        result["_residual_on_v2"] = bypass_poc(version="v2")
        result["_residual_blocked_on_v2"] = not bypass_poc(version="v2").get("flag_echo")
        result["_original_blocked_on_v2"] = not original_poc(version="v2").get("flag_echo")
    result["_flag"] = FLAG
    if not keep_up:
        _compose(*allp, "down", "-v", "--rmi", "all", env={"PCB_FLAG": "teardown"})
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-gate", action="store_true")
    ap.add_argument("--with-v2", action="store_true")
    ap.add_argument("--keep-up", action="store_true")
    ap.add_argument("--probe", choices=["orig", "bypass"])
    ap.add_argument("--version", default="v1")
    a = ap.parse_args()
    if a.probe:
        fn = original_poc if a.probe == "orig" else bypass_poc
        print(json.dumps(fn(version=a.version), indent=2, default=str))
    elif a.run_gate:
        print(json.dumps(run_gate(with_v2=a.with_v2, keep_up=a.keep_up), indent=2, default=str))
    else:
        print(json.dumps(gate(), indent=2, default=str))
