#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-27837 residual exploit -- the incomplete-fix bypass of dottie@2.0.4.

The CVE-2023-26132 fix (V1 = dottie@2.0.4) only added `if (pieces[0] === '__proto__') return;` -- it
inspects ONLY the first path segment, and only for the exact key `__proto__`. Placing `__proto__` at
any NON-first position slips straight past it. The crafted path `x.__proto__.pcbUnlock` has
pieces[0] = 'x' (guard passes), then during traversal `target.x['__proto__'] = {}` replaces
`target.x`'s prototype with a fresh object and writes `pcbUnlock` onto it -- the assignment lands on a
PROTOTYPE (prototype pollution), so `target.x` inherits `pcbUnlock`. The benign default-deny gate sees
the write landed on a prototype and releases ${PCB_FLAG}. This is CVE-2026-27837: the fix guarded only
the first path segment.

On V2 (dottie@2.0.7, the CVE-2026-27837 fix) the guard is
`DANGEROUS_KEYS = ['__proto__','constructor','prototype']; if (pieces.some(p => DANGEROUS_KEYS.indexOf(p)
!== -1)) return;` -- it rejects the dangerous key at ANY position, so `x.__proto__.pcbUnlock` returns
without writing and nothing is polluted. BLOCKED (negative control).
"""


def candidate():
    return {
        "path": "x.__proto__.pcbUnlock",
        "probe_id": "residual-cve-2026-27837-proto-non-first-segment",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
