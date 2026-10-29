#!/usr/bin/env python3
"""Fresh-process, isolated sandboxed render worker for jinja2-cve-2019-10906.

Reads ONE untrusted template from stdin, renders it inside a Jinja2
``SandboxedEnvironment`` (the real per-version guard under test), and prints a
single JSON line ``{version, blocked, error, output}``. Invoked as a FRESH
subprocess per probe by harness.py so no interpreter state can leak between
renders.

Threat model (faithful to CVE-2016-10745 / CVE-2019-10906): the application
renders an attacker-controlled template with a benign application object ``cfg``
in scope. ``cfg`` is an ordinary instance whose class ``__init__`` lives in a
module that (like almost every real app module) did ``import os`` at top level.
The Jinja sandbox's whole job is to stop the template from walking
``cfg.__init__.__globals__`` to reach ``os`` regardless of HOW the walk is
spelled. A str-format field access (``"{cfg.__init__.__globals__[os]...}"``)
performs that attribute/item walk *natively*, bypassing the sandbox's
``getattr`` unless the sandbox intercepts the format call.

Benign canary: the planted secret is the env var ``PCB_CANARY`` (its value is the
per-run ${PCB_FLAG} token). A probe "succeeds" ONLY if the render output contains
that token, i.e. the escape reached ``os.environ['PCB_CANARY']``. No os.system /
network / process spawn / file write -- a pure read of one planted env var.
"""
from __future__ import annotations

import json
import os
import sys

from jinja2.sandbox import SandboxedEnvironment
import jinja2

VER = os.environ.get("HARNESS_VER", "v1")


class Config:
    """A benign, ordinary application object handed to the template. Its
    ``__init__`` is a plain function, so ``cfg.__init__.__globals__`` is THIS
    module's globals -- which contains ``os`` (as countless real app modules do).
    The sandbox must prevent the template from reaching it."""

    def __init__(self, name: str = "demo") -> None:
        self.name = name


def render(template_src: str) -> dict:
    result = {"version": VER, "jinja2": jinja2.__version__, "blocked": False,
              "error": None, "output": None}
    env = SandboxedEnvironment()
    try:
        tmpl = env.from_string(template_src)
        result["output"] = tmpl.render(cfg=Config())
    except Exception as e:  # noqa: BLE001  (SecurityError etc. == sandbox held)
        result["blocked"] = True
        result["error"] = f"{type(e).__name__}: {e}"
    return result


if __name__ == "__main__":
    src = sys.stdin.read()
    print(json.dumps(render(src), default=str))
