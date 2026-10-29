#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:39610",
    "v1": "http://127.0.0.1:39611",
}
import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
_DATA_B64_RE = re.compile(r'data:[^;"\'\\]*;base64,([A-Za-z0-9+/=]+)')
_CONTENT_RE = re.compile(r'content="([^"]*)"', re.IGNORECASE)
_OG_IMAGE_RE = re.compile(r'<meta[^>]*property="og:image"[^>]*>', re.IGNORECASE)
BASE = {
    "v0": "http://127.0.0.1:39610",
    "v1": "http://127.0.0.1:39611",
}
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
def run_probe(candidate, *, version="v1"):
    
    base = BASE.get(version)
    if base is None:
        return {"version": version, "error": "no env for this version"}
    avatar = candidate["avatar"] if isinstance(candidate, dict) else str(candidate)
    enc = urllib.parse.quote(avatar, safe="")

    
    _pc, page = _get(f"{base}/ssrf?avatar={enc}")
    og_url = _extract_og_image_url(page)
    if not og_url:
        return {"version": version, "avatar": avatar, "error": "no og:image url", "page_head": page[:200]}

    
    svg_url = _to_local_svg(og_url, base)
    status, body = _get(svg_url)
    reached = _reaches_flag(body)
    out = {
        "version": version,
        "avatar": avatar,
        "og_image_url": og_url,
        "render_url": svg_url,
        "render_status": status,
        "reached_flag": reached,
    }
    # flag channel for the auto-adapted judge: the rendered body, PLUS any base64-decoded
    # data-URI payloads (the module base64-inlines the fetched sidecar bytes, so the flag
    # may only exist inside a data URI). Raw-text search needs the decoded form surfaced.
    out["resp"] = _flag_channel_text(body)
    if reached:
        out["flag"] = X          
    else:
        out["blocked"] = True       
    return out
def _flag_channel_text(svg_body: str) -> str:
    
    texts = [svg_body]
    for b64 in _DATA_B64_RE.findall(svg_body):
        try:
            dec = base64.b64decode(b64, validate=False).decode("utf-8", "replace")
        except Exception:  
            continue
        texts.append(dec)
    return "\n".join(texts)
def _reaches_flag(svg_body: str) -> bool:
    
    if X in svg_body:
        return True
    for b64 in _DATA_B64_RE.findall(svg_body):
        try:
            dec = base64.b64decode(b64, validate=False).decode("utf-8", "replace")
        except Exception:  
            continue
        if X in dec:
            return True
    return False
def _get(url: str, timeout: int = 30):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  
        return None, f"<get-error: {e}>"
def _to_local_svg(og_url: str, base: str) -> str:
    
    
    path_q = re.sub(r'^https?://[^/]+', '', og_url)
    if '?' in path_q:
        path, q = path_q.split('?', 1)
        path = re.sub(r'\.png$', '.svg', path)
        return f"{base}{path}?{q}"
    return f"{base}{re.sub(r'.png$', '.svg', path_q)}"
def _extract_og_image_url(html: str) -> str:
    m = _OG_IMAGE_RE.search(html)
    if not m:
        return ""
    c = _CONTENT_RE.search(m.group(0))
    return c.group(1) if c else ""


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