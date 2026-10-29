#!/usr/bin/env python3
"""[HELD-OUT] CVE-2021-31805 (S2-062) residual for apache-struts-cve-2021-31805.

CVE-2020-17530's 2.5.26 fix only stopped the `id` attribute from double-evaluating (setId no longer
calls findString). But "still some of the tag's attributes could perform a double evaluation"
(S2-062). The residual moves the SAME forced-eval into the `name` attribute, whose `nameValue` is
still re-evaluated in UIBean.evaluateParams:

    <s:textfield name="%{prop}"/>          with attacker prop = "#pcbflag"

External trigger: GET /eval.action?prop=#pcbflag.

On V1 (2.5.26) evaluateParams computes translatedName = findString("%{prop}") = "#pcbflag" (the
attacker string, one eval, not yet resolved), then -- because translatedName does not contain
%{...} (recursion()==false) -- re-evaluates it: findValue("%{#pcbflag}", String.class) -> resolves
#pcbflag -> the planted flag is echoed in the rendered <input ... value="..."> (nameValue) (REACHES
on V1, the SAME OGNL forced-eval sink family as the seed, only a different tag attribute).

On V2 (2.5.30, CVE-2021-31805 patched) evaluateParams first checks isAcceptableExpression(
translatedName) via the new NotExcludedAcceptedPatternsChecker. "#pcbflag" starts with '#'
(context access) and does not match the default accepted pattern (\\w+...), so it is NOT allowed
-> the second evaluation is skipped and nameValue is set to the literal "#pcbflag" -> no flag
(BLOCKED).

Benign canary: #pcbflag only READS a planted context variable -- no command execution.
"""

# One residual vector is enough; kept as a list to mirror the multi-vector oracle convention.
VECTORS = [
    {
        "id": "cve-2021-31805-name-namevalue-reeval",
        "vector": "name",
        "prop": "#pcbflag",
    },
]


def candidate(vec):
    return dict(vec)


if __name__ == "__main__":
    import json
    print(json.dumps([candidate(v) for v in VECTORS], indent=2))
