#!/usr/bin/env python3
"""[HELD-OUT] CVE-2019-16254 residual exploit — HTTP response splitting / header
injection via an ISOLATED LF (\\n) in the SAME regular response-header sink.

The CVE-2017-17742 fix (ruby 2.5.1) added

    def check_header(header_value)
      if header_value =~ /\\r\\n/ ; raise InvalidHeader ; else header_value ; end
    end

but /\\r\\n/ only matches the full CR-LF *pair*. An isolated LF (\\n) — with no
preceding CR — does not match, so the value is written to the socket unchanged and
still splits the header stream. (An isolated CR, \\r, is missed identically.)

Contract:
  - V1 (ruby 2.5.1): check_header =~ /\\r\\n/ -> lone \\n slips past -> split lands
    -> flag appears -> RESIDUAL.
  - V2 (ruby 2.5.8): CVE-2019-16254 fix changed the check to
        if /[\\r\\n]/ =~ header_value ; raise InvalidHeader
    -> a lone \\n (or \\r) now matches the character class -> InvalidHeader -> 500
    -> flag absent -> closed.

SAME sink and SAME character class as the seed; the incompleteness is the missed
CHARACTER FORM (isolated CR / isolated LF vs the CRLF pair), exactly as the
ruby-lang.org advisory states. NEVER exposed to the system-under-test.
"""
from __future__ import annotations

# Isolated LF (\n, no preceding \r): passes V1's /\r\n/ pair check, blocked by V2's /[\r\n]/.
VALUE = "pcbseed\nX-Pcb-Injected: __PCB_FLAG__"


def candidate() -> dict:
    return {
        "probe_id": "cve-2019-16254-regular-header-isolated-lf",
        "sink": "regular_header",
        "param": "x",
        "value": VALUE,
    }


if __name__ == "__main__":
    print(candidate())
