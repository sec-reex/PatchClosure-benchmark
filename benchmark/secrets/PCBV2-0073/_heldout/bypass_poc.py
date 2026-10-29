#!/usr/bin/env python3
r"""[HELD-OUT] CVE-2026-48795 residual — nested-segment bypass of the CVE-2026-25754 fix.

The CVE-2026-25754 fix (present on V1 = @adonisjs/bodyparser 10.1.4) makes FormFields store fields
in `Object.create(null)`, which defeats a DIRECT `__proto__.x` field (the null-proto object has no
`Object.prototype` to reach). But the assignment is still `lodash.set(#fields, key, value)` with the
attacker-controlled field name as the path, and lodash builds MISSING intermediate containers as
PLAIN `{}`. So a field named

    user.__proto__.pcbPolluted = <FLAG>

first creates `#fields.user = {}` (an ORDINARY object, prototype = Object.prototype), then resolves
`user.__proto__` to `Object.prototype` and assigns `pcbPolluted = <FLAG>` onto it. Object.prototype
is polluted again -> `({}).pcbPolluted === <FLAG>` on V1. A non-dangerous first segment before
`__proto__` (or `constructor.prototype`) is all it takes; this is exactly GHSA-qcm7-3vpr-hj5h:
"payloads containing a non-dangerous segment before __proto__ or constructor.prototype, such as
user.__proto__.polluted, still lead to Object.prototype pollution."

CVE-2026-48795 fix (V2 = 10.1.5) adds a key sanitizer at the top of `FormFields.add()`:
`if (lodash.toPath(key).some(seg => {__proto__,prototype,constructor}.has(seg))) return;` — so ANY
segment named `__proto__`/`prototype`/`constructor`, nested or not, drops the field before
`lodash.set` runs -> the residual is closed (canary stays undefined).

Contract: pollutes Object.prototype on V1 (flag observed); closed on V2.
"""
from __future__ import annotations


def candidate(flag: str) -> dict:
    """Multipart field whose NAME nests the dangerous segment behind a benign one:
    `user.__proto__.pcbPolluted` -> lodash builds a plain `{}` at `user`, then hits Object.prototype."""
    return {
        "probe_id": "cve-2026-48795-nested-proto-segment",
        "method": "POST",
        "path": "/probe",
        "field_name": "user.__proto__.pcbPolluted",
        "field_value": flag,
    }


if __name__ == "__main__":
    print(candidate("PCBFLAG_demo")["field_name"])
