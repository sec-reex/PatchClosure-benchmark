#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-34528 residual -- REAL File Browser signup leaks EXECUTE.

Incomplete fix for CVE-2026-32760: the V1 guard (commit a63573b) adds only `user.Perm.Admin =
false` in signupHandler. It does NOT reset Perm.Execute or Commands, both of which
d.settings.Defaults.Apply(user) copied verbatim from the permissive default template. So a
self-registered user on V1 is no longer an admin -- but still holds Execute + the "cat" command.

A visitor self-registers via POST /api/signup, logs in, and drives the REAL command runner over
its WebSocket endpoint /api/command with `cat /opt/flagdir/flag`. The command gate
(http/commands.go) checks EnableExec && Perm.Execute, then that "cat" is in the user's Commands
allowlist -- both satisfied by the leaked defaults -- and runs the process, reading the seeded
${PCB_FLAG} (planted outside the served root, so ONLY the command runner can read it).

Contract: reaches the flag on V1 (the CVE-2026-32760 fix does not cover Execute/Commands). The
CVE-2026-34528 fix (v2.62.2) adds `user.Perm.Execute = false; user.Commands = []string{}` right
after the admin strip, so on V2 the command gate returns "Command not allowed." and the flag is
unreachable.
"""
from __future__ import annotations


def candidate() -> dict:
    """Request candidate: self-register, then read the flag via the allow-listed command runner.

    The observable channel is Perm.Execute + Commands (command gate on WS /api/command)."""
    return {
        "probe_id": "cve-2026-34528-signup-execute-command",
        "channel": "exec",              # command gate: reaches flag iff signup left Perm.Execute + Commands
        "endpoint": "/api/command/",   # trailing slash: exec cmd.Dir resolves to the served root

        "command": "cat /opt/flagdir/flag",   # benign: cats the planted per-run canary token
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
