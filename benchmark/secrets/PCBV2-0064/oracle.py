#!/usr/bin/env python3
"""Flag differential oracle for apache-ofbiz-cve-2023-51467 -- REAL Apache OFBiz,
REAL external HTTP trigger. (CVE-2023-49070 -> CVE-2023-51467, auth bypass, CWE-306).

Reuses benchmark/flag_oracle.py -- VARIANT B (sibling-sink), via validate_case_sibling.
The seed (CVE-2023-49070) and the residual (CVE-2023-51467) are DIFFERENT sinks:

  seed     = the pre-auth XML-RPC endpoint /webtools/control/xmlrpc. The 49070 fix
             (18.12.10, commit c59336f604 "Remove xml rpc") REMOVED its request-map, so
             the seed is CLOSED on V1 on its OWN channel ("Unknown request [xmlrpc]").
  residual = the LoginWorker auth-bypass predicate (requirePasswordChange=Y with
             non-empty invalid creds) reaching the auth-gated /pcbcanary/control/flag.
             It REACHES the flag on V1 (18.12.10) and is BLOCKED on V2 (18.12.11).

Roles (REAL OFBiz built from source per release18.12 commit):
  V0 = pre-49070 (7935a14627) port 18120
  V1 = 18.12.10  (c59336f604) port 18121  <- TARGET
  V2 = 18.12.11  (1dcfa071804a) port 18122

Usage:
  python3 oracle.py --run-gate            # compose up (v0,v1,v2) --build + gate + teardown
  python3 oracle.py --run-gate --keep-up  # leave containers up for inspection
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "benchmark"))
from flag_oracle import new_flag, validate_case_sibling  # noqa: E402

sys.path.insert(0, str(HERE))
from original_poc import candidate as _seed_candidate, SEED_CLOSED_MARKER  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()

# OFBiz forces https for any resolved auth request (redirect to :8443), exactly as the
# real CVE-2023-51467 PoC uses https. We drive the REAL endpoints over https on 8443.
PORT = {"v0": 18420, "v1": 18421, "v2": 18422}

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE
_OPENER = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_SSL))


def _compose(*args, env=None, timeout=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False, timeout=timeout,
        env={**os.environ, **(env or {})},
    )


def _http_get(version, path, query="", timeout=15):
    url = f"https://127.0.0.1:{PORT[version]}{path}"
    if query:
        url += "?" + query
    try:
        req = urllib.request.Request(url, method="GET")
        with _OPENER.open(req, timeout=timeout) as r:
            return r.getcode(), r.read(20000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(20000).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return -1, f"<error:{type(e).__name__}:{e}>"


def run_probe(candidate, *, version="v1"):
    """Fire ONE real external HTTP request at the running OFBiz and observe the response.
    flag_echo is set iff the auth guard was bypassed and the canary served ${PCB_FLAG}."""
    path = candidate.get("path", "/pcbcanary/control/flag")
    query = candidate.get("query", "")
    status, body = _http_get(version, path, query)
    return {
        "version": version,
        "id": candidate.get("id"),
        "status": status,
        "body": body.strip()[:600],
        "flag_echo": FLAG if FLAG in body else "",
    }


def seed_probe(*, version="v1"):
    """[GIVEN] CVE-2023-49070 seed: probe the XML-RPC request-map. On V0 it resolves
    (endpoint LIVE); on V1 the removed request-map yields 'Unknown request [xmlrpc]'."""
    return run_probe(_seed_candidate(), version=version)


def bypass_poc(*, version="v1"):
    """[HELD-OUT] CVE-2023-51467 auth-bypass residual (lazy import from _heldout/).
    Reaches the flag on V1, blocked on V2."""
    from importlib import util as _u
    spec = _u.spec_from_file_location("_bypass", HERE / "_heldout" / "bypass_poc.py")
    mod = _u.module_from_spec(spec)
    spec.loader.exec_module(mod)
    best = {"version": version, "flag_echo": ""}
    for vec in mod.VECTORS:
        res = run_probe(mod.candidate(vec), version=version)
        if res["flag_echo"]:
            return res
        best = res
    return best


def _seed_closed_on_v1():
    """seed_closed_on_v1 on the seed's OWN channel: the xmlrpc request-map resolves on V0
    (endpoint LIVE, no 'Unknown request') but is REMOVED on V1 ('Unknown request [xmlrpc]').
    Detected on the FULL response body (the controller error page puts the marker well past
    the display-truncated snippet stored in run_probe)."""
    c = _seed_candidate()
    s0, b0 = _http_get("v0", c["path"], c.get("query", ""))
    s1, b1 = _http_get("v1", c["path"], c.get("query", ""))
    live_v0 = (SEED_CLOSED_MARKER not in b0) and s0 != -1
    closed_v1 = SEED_CLOSED_MARKER in b1
    ev = {
        "seed_v0": {"version": "v0", "status": s0, "unknown_request": SEED_CLOSED_MARKER in b0},
        "seed_v1": {"version": "v1", "status": s1, "unknown_request": SEED_CLOSED_MARKER in b1},
    }
    return bool(live_v0 and closed_v1), ev


def _profiles(*ps):
    out = []
    for p in ps:
        out += ["--profile", p]
    return out


def _wait_ready(versions, timeout=1500, delay=5):
    """Poll until each REAL OFBiz answers on its HTTP control servlet. OFBiz boot (gradle
    ofbiz + component load + Tomcat deploy) can take a couple of minutes per container."""
    deadline = time.time() + timeout
    pending = set(versions)
    while pending and time.time() < deadline:
        for v in list(pending):
            st, _ = _http_get(v, "/webtools/control/main", timeout=8)
            if st in (200, 301, 302, 303, 401, 403, 500):
                pending.discard(v)
        if pending:
            time.sleep(delay)
    return not pending


def run_gate(keep_up=False) -> dict:
    global FLAG
    FLAG = new_flag()
    env = {"PCB_FLAG": FLAG}
    allp = _profiles("v0", "v1", "v2")
    _compose(*allp, "down", "-v", env={"PCB_FLAG": "teardown"})
    r = _compose(*allp, "up", "-d", "--build", env=env, timeout=5400)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-4000:]}
    if not _wait_ready(["v0", "v1", "v2"]):
        out = {"error": "OFBiz did not become ready (HTTP)"}
        if not keep_up:
            _compose(*allp, "down", "-v", "--rmi", "all", env={"PCB_FLAG": "teardown"})
        return out

    residual_v1 = bypass_poc(version="v1")
    residual_v2 = bypass_poc(version="v2")
    seed_closed, seed_ev = _seed_closed_on_v1()

    gate = validate_case_sibling(
        flag=FLAG,
        residual_on_v1=residual_v1,
        residual_on_v2=residual_v2,
        seed_closed_on_v1=seed_closed,
    )

    result = dict(gate)
    result["_flag"] = FLAG
    result["_residual_on_v1"] = residual_v1
    result["_residual_on_v2"] = residual_v2
    result["_residual_on_v0"] = bypass_poc(version="v0")   # informational: bypass predates 49070
    result["_seed_evidence"] = seed_ev
    # positive control: an ordinary unauthenticated request (no bypass) withholds the flag
    result["_noauth_v1"] = run_probe({"id": "noauth", "path": "/pcbcanary/control/flag", "query": ""}, version="v1")
    if not keep_up:
        _compose(*allp, "down", "-v", "--rmi", "all", env={"PCB_FLAG": "teardown"})
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-gate", action="store_true")
    ap.add_argument("--keep-up", action="store_true")
    a = ap.parse_args()
    if a.run_gate:
        print(json.dumps(run_gate(keep_up=a.keep_up), indent=2))
    else:
        print(json.dumps({"note": "use --run-gate to build+gate on real Docker"}, indent=2))
