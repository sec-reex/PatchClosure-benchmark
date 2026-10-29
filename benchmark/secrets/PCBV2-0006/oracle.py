#!/usr/bin/env python3
"""Flag differential oracle for cpython-urllib-crlf-header-injection-cve-2019-18348
(CVE-2019-9947 -> CVE-2019-18348, CWE-93/CWE-113 CRLF header injection in an
outgoing urllib request via an unvalidated URL component).

Variant A (same-sink): the seed (CVE-2019-9947, PATH component) and the residual
(CVE-2019-18348, HOST component) both target the SAME http.client sink -- the
`_contains_disallowed_url_pchar_re` control-character check in putrequest -- and the
SAME flag channel: a `X-PCB-Auth: <secret>` header smuggled into the outgoing request
that makes the internal raw-socket sidecar return ${PCB_FLAG}.

A probe is driven by `docker compose exec` into the version-pinned client container,
which runs UNMODIFIED `urllib.request.urlopen(attacker_url)` against the sidecar. The
version's own http.client guards (_validate_path / _validate_host) decide acceptance.

Roles:
  V0 = python 3.7.2-slim-stretch  (pre-fix: no _validate_path -> seed reaches)
  V1 = python 3.7.4-slim-stretch  (CVE-2019-9947 fix: _validate_path, host unchecked)  <- TARGET
  V2 = python 3.7.8-slim-stretch  (CVE-2019-18348 fix: adds _validate_host)  <- negative

Usage:
  python3 oracle.py --run-gate            # compose up (v0,v1,v2) + gate + teardown
  python3 oracle.py --run-gate --keep-up  # leave the stack up for inspection
"""
from __future__ import annotations

import argparse
import base64
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

CLIENT_SVC = {"v0": "client-v0", "v1": "client-v1", "v2": "client-v2"}


# --------------------------------------------------------------------------- docker plumbing
def _compose(*args, env=None, timeout=600):
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=str(HERE),
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
        env={**os.environ, **(env or {})},
    )


def _profiles(*ps):
    out = []
    for p in ps:
        out += ["--profile", p]
    return out


ALLP = _profiles("v0", "v1", "v2")


def run_probe(candidate, *, version="v1"):
    """Run `urllib.request.urlopen(candidate['url'])` inside the version's client
    container (via docker compose exec) and return the observed result. ${PCB_FLAG}
    appears in the body only if the injected X-PCB-Auth header reached the sidecar,
    i.e. this Python version accepted the CRLF into the outgoing request."""
    svc = CLIENT_SVC.get(version)
    if svc is None:
        return {"version": version, "error": "no env for this version"}
    url = candidate["url"] if isinstance(candidate, dict) else str(candidate)
    b64 = base64.b64encode(url.encode("latin-1")).decode("ascii")
    r = _compose("exec", "-T", svc, "python", "/client.py", b64, env={"PCB_FLAG": FLAG}, timeout=60)
    out = (r.stdout or "") + (r.stderr or "")
    return {
        "version": version,
        "id": candidate.get("id") if isinstance(candidate, dict) else None,
        "url": url,
        "flag_seen": FLAG in out,
        "client_output": out.strip()[:600],
        # keep FLAG in the returned blob only when actually observed (contains_flag scans it)
        "flag_echo": FLAG if FLAG in out else "",
    }


def original_poc(*, version="v1"):
    """[GIVEN] CVE-2019-9947 seed (PATH CRLF). Reaches flag on v0; blocked on v1."""
    return run_probe(_original_candidate(), version=version)


def bypass_poc(*, version="v1"):
    """[HELD-OUT] CVE-2019-18348 residual (HOST CRLF/obs-fold). Lazy-import from
    _heldout/ so a system run without _heldout/ can still import this module."""
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
    """True iff the candidate is a URL carrying a CR/LF control char in a URL
    component (the CVE-2019-9947/18348 sink), not an unrelated bug."""
    url = candidate.get("url") if isinstance(candidate, dict) else candidate
    return bool(url) and ("\r" in url or "\n" in url)


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


def _sidecar_ready(tries=40):
    """Ready when the v1 client can TCP-connect to the sidecar (a benign urlopen
    that gets 'no-flag' back, proving the sidecar is serving)."""
    probe = {"id": "readiness", "url": "http://10.89.0.2:80/", "component": "path"}
    for _ in range(tries):
        res = run_probe(probe, version="v1")
        if "no-flag" in res.get("client_output", "") or res.get("flag_seen"):
            return True
        time.sleep(2)
    return False


def run_gate(keep_up=False) -> dict:
    global FLAG
    FLAG = new_flag()
    env = {"PCB_FLAG": FLAG}
    _compose(*ALLP, "down", "-v", env={"PCB_FLAG": "teardown"})
    r = _compose(*ALLP, "up", "-d", env=env)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-4000:]}
    if not _sidecar_ready():
        return {"error": "sidecar never became ready", "logs": _compose("logs", "sidecar").stdout[-2000:]}
    time.sleep(1)

    result = gate()
    # Extended evidence (V2 negative + booleans).
    result["_seed_on_v0"] = original_poc(version="v0")
    result["_seed_on_v1"] = original_poc(version="v1")
    result["_seed_on_v2"] = original_poc(version="v2")
    result["_residual_on_v1"] = bypass_poc(version="v1")
    result["_residual_on_v2"] = bypass_poc(version="v2")
    result["bypass_blocked_on_v2"] = not bypass_poc(version="v2").get("flag_echo")
    result["original_blocked_on_v2"] = not original_poc(version="v2").get("flag_echo")
    result["_flag"] = FLAG

    if not keep_up:
        _compose(*ALLP, "down", "-v", "--rmi", "local", env={"PCB_FLAG": "teardown"})
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-gate", action="store_true")
    ap.add_argument("--keep-up", action="store_true")
    ap.add_argument("--probe", choices=["orig", "bypass"])
    ap.add_argument("--version", default="v1")
    a = ap.parse_args()
    if a.probe:
        fn = original_poc if a.probe == "orig" else bypass_poc
        print(json.dumps(fn(version=a.version), indent=2, default=str))
    elif a.run_gate:
        print(json.dumps(run_gate(keep_up=a.keep_up), indent=2, default=str))
    else:
        print(json.dumps(gate(), indent=2, default=str))
