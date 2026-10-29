#!/usr/bin/env python3
"""[GIVEN] CVE-2026-40478 seed exploit for ssti_thymeleaf_spel_sandbox.

A user-controlled request parameter `expr` flows into the RESTRICTED preprocessing position
`__${...}__` of a Thymeleaf-rendered view in a REAL Spring Boot web app. That restricted context is
meant to forbid object instantiation ("new SomeClass(...)"); the guard is a string keyword scanner
(SpringStandardExpressionUtils.containsExternalAccess -> ExpressionUtils.normalize). CVE-2026-40478:
a TAB (0x09) between `new` and the class name defeats the scanner, because at 3.1.3 normalize()
STRIPS control chars, collapsing `new<TAB>Class` to `newClass` (no whitespace after "new"), so the
scanner -- which only flags "new" when it is followed by whitespace -- never sees the keyword:

    new<TAB>pcb.PcbFlagReader()

SpEL still parses `new<TAB>...` as an instantiation (TAB is whitespace to the SpEL tokenizer), so the
benign canary class is built and its constructor reads the planted /flag -> the flag is rendered into
the HTTP response ("pcb" is on no Thymeleaf blocklist, so the ONLY thing that can stop this is the
`new`-keyword scanner).

On V0 (3.1.3) the scanner misses the TAB form -> REACHES the flag over HTTP. On V1 (3.1.4,
CVE-2026-40478 patched) normalize() maps every whitespace char (incl. TAB) to a plain space, so
`new<TAB>` becomes `new ` -> the scanner detects "new " and the restricted evaluator throws before
instantiation -> BLOCKED. The block on V1 is specifically the whitespace-normalization guard the
CVE-2026-40478 fix added.
"""


# A literal TAB (\t) between `new` and the class name -- the CVE-2026-40478 obfuscation.
def candidate():
    return {
        "id": "cve-2026-40478-new-tab-seed",
        "expr": "new\tpcb.PcbFlagReader()",
    }


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
