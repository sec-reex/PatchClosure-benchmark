#!/usr/bin/env python3
"""[GIVEN] CVE-2020-17530 (S2-061) seed exploit for apache-struts-cve-2021-31805.

The classic S2-061 vector: forced double OGNL evaluation of a UI tag's `id` attribute. A developer
forced-evaluates an attacker-controlled action property in the attribute:

    <s:textfield id="%{prop}"/>          with attacker prop = "%{#pcbflag}"

External trigger: GET /eval.action?prop=%{#pcbflag}. The action binds `prop` (raw string, not
evaluated) and plants the benign #pcbflag context var; eval.jsp renders the tag.

On V0 (struts2-core 2.5.25) the `id` attribute is evaluated TWICE: once in setId
(this.id = findString(id)) and again in evaluateParams (findStringIfAltSyntax(id)). The first eval
turns "%{prop}" into the attacker string "%{#pcbflag}"; the second eval resolves #pcbflag -> the
planted flag is echoed in the rendered <input id="..."> (REACHES).

On V1 (2.5.26, CVE-2020-17530 patched) setId no longer evaluates (this.id = id), so the `id`
attribute is evaluated only ONCE in evaluateParams: "%{prop}" -> "%{#pcbflag}" (a literal
expression string, not resolved) -> no flag (BLOCKED). The block on V1 is specifically the setId
double-eval fix.

Benign canary: prop's inner expression #pcbflag only READS a planted context variable -- no
command execution.
"""

CANDIDATE = {
    "id": "cve-2020-17530-id-double-eval",
    "vector": "id",
    "prop": "%{#pcbflag}",
}


def candidate():
    return dict(CANDIDATE)


if __name__ == "__main__":
    import json
    print(json.dumps(candidate(), indent=2))
