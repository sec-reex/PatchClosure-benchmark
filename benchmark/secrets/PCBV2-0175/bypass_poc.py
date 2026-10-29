#!/usr/bin/env python3
r"""[HELD-OUT] CVE-2022-21231 residual -- nested-array (type-confusion) bypass of the 1.1.1 fix.

real-app-http: fired as REAL EXTERNAL HTTP against the running Express service:
  POST /set  {"path": [["__proto__"],"isAdmin"], "value": true}
then GET /check observes whether Object.prototype was polluted. The service calls the REAL published
deep-get-set deep({}, path, value) on the attacker JSON -- no in-process probe, no source-lift.

The CVE-2020-7715 fix (present on V1 = deep-get-set 1.1.1) guards each path segment with a strict `!==`
STRING comparison and NO type coercion:

    function isSafeKey (key) { return key !== '__proto__' && key !== 'prototype' && key !== 'constructor'; }
    ... if (!isSafeKey(key)) return;

A path whose FIRST segment is itself an array -- `[["__proto__"], "isAdmin"]` -- makes the dangerous
key the ARRAY `["__proto__"]`. `["__proto__"] !== '__proto__'` is TRUE (array vs string), so isSafeKey
returns true and the guard PASSES it; then the native deref `obj[key]` coerces the array back to the
string '__proto__' (Array.prototype.toString joins to "__proto__"), so the walk still steps onto
Object.prototype and the leaf write assigns `isAdmin = true` onto it = CWE-843 type confusion. A later
GET /check sees `({}).isAdmin === true` and releases the flag on V1.

This is CVE-2022-21231, which SNYK-JS-DEEPGETSET-2342655 states 'derives from an incomplete fix of
CVE-2020-7715'. Advisory PoC: deep({}, [["__proto__"], 'polluted'], 'success').

CVE-2022-21231 fix (V2 = deep-get-set 1.1.2) replaces isSafeKey with an array-aware isUnsafeKey:

    function isUnsafeKey (key) {
      return (Array.isArray(key) && key[0] === '__proto__') || key === '__proto__'
        || key === 'constructor' || key === 'prototype';
    }
    ... if (isUnsafeKey(key)) return;

The nested-array segment matches `(Array.isArray(key) && key[0] === '__proto__')` FIRST, so the guard
returns BEFORE any write -- the residual is rejected (/check stays null, no flag).

Contract: reaches the flag on V1; closed on V2.
"""
from __future__ import annotations


def candidate(flag: str) -> dict:
    """A POST /set whose first path segment is a NESTED ARRAY of the dangerous name."""
    return {
        "probe_id": "cve-2022-21231-nested-array-proto",
        "method": "POST",
        "path_route": "/set",
        "path": [["__proto__"], "isAdmin"],
        "value": True,
    }


if __name__ == "__main__":
    print(candidate("PCBFLAG_demo"))
