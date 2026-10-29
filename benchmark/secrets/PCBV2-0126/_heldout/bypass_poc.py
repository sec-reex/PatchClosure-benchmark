#!/usr/bin/env python3
"""[HELD-OUT] Residual = CVE-2021-23369 (SNYK-JS-HANDLEBARS-1056767, GH-1633).

The CVE-2019-20920 fix guarded the `lookup` helper (and default-mode path
resolution) via `container.lookupProperty`, but it left the STRICT-mode terminal
path lookup untouched. In lib/handlebars/runtime.js the `strict` container fn
still did `return obj[name];` -- bypassing the proto-access filter for the final
segment of a strict-compiled path (compiler `strictLookup` emits
`container.strict(stack, terminal)`; intermediates go through the guarded
`lookupProperty`, the terminal does not).

So compiling the SAME proto-property read with `{strict:true}` reaches the
non-own canary on 4.7.6 (V1) even though the lookup-helper seed is blocked.
The 4.7.7 fix (commit b6d3de7) changed `strict` to
`return container.lookupProperty(obj, name);`, routing the strict terminal
through the same guard -> blocked on V2. This matches handlebars' own security
regression test, which added `describe('in strict-mode', ...)` to the
proto-property-access suite in the fix commit.
"""


def candidate():
    return {
        "probe_id": "residual-cve-2021-23369-strict-terminal-lookup",
        # strict-mode single-segment path; terminal goes through container.strict
        # (obj[name], unguarded on 4.7.6) instead of lookupProperty.
        "template": "{{pcbCanary}}",
        "strict": True,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate()))
