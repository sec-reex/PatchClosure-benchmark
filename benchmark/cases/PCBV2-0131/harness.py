#!/usr/bin/env python3
"""Faithful-core Jinja2 sandbox harness for jinja2-cve-2019-10906.

Models the CVE-2016-10745 / CVE-2019-10906 sink directly: an application renders
an attacker-controlled template string inside a Jinja2 ``SandboxedEnvironment``.
There is no LLM / app logic to stub -- the guard under test IS Jinja2's own
``SandboxedEnvironment.call`` / ``inspect_format_method`` machinery, exercised
through a genuine ``env.from_string(src).render(cfg=Config())`` call, with the
Jinja2 version pinned per profile:

  HARNESS_VER=v0  jinja2 2.7.3   -> pre-CVE-2016-10745: call() has NO format
                                    interception; native str.format AND
                                    str.format_map both escape the sandbox.
  HARNESS_VER=v1  jinja2 2.8.1   -> CVE-2016-10745 fix: inspect_format_method
                                    intercepts ONLY `.format`
                                    (`callable.__name__ != 'format'`); `.format_map`
                                    slips through natively -> residual open  <- TARGET
  HARNESS_VER=v2  jinja2 2.10.1  -> CVE-2019-10906 fix: guard widened to
                                    `not in ('format', 'format_map')` -> both
                                    intercepted -> residual blocked (negative control)

Endpoint:  POST /render   body = the attacker-supplied template (text/plain).
Response:  JSON {version, jinja2, blocked, error, output}. The planted
           ${PCB_CANARY} (= per-run ${PCB_FLAG} token) appears in `output` ONLY if
           the sandbox let a str-format field walk reach os.environ (escape).

Isolation: every render runs in a FRESH `render_once.py` subprocess so no
interpreter state can leak between probes.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import jinja2

VER = os.environ.get("HARNESS_VER", "v1")
RENDER_ONCE = str(Path(__file__).resolve().parent / "render_once.py")


def run_render(template_src: str) -> dict:
    """Dispatch ONE render to a fresh, isolated subprocess and return its JSON."""
    try:
        proc = subprocess.run(
            [sys.executable, RENDER_ONCE],
            input=template_src.encode("utf-8"),
            capture_output=True,
            timeout=25,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired:
        return {"version": VER, "blocked": True, "error": "timeout", "output": None}
    out = proc.stdout.decode("utf-8", "replace").strip()
    try:
        return json.loads(out.splitlines()[-1]) if out else {
            "version": VER, "blocked": True,
            "error": f"no output; stderr={proc.stderr.decode('utf-8','replace')[:200]}",
            "output": None,
        }
    except Exception as e:  # noqa: BLE001
        return {"version": VER, "blocked": True, "error": f"harness-parse: {e}; raw={out[:200]}",
                "output": None}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code: int, obj: dict):
        blob = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)

    def do_GET(self):
        if urlparse(self.path).path == "/":
            self._send(200, {"ok": True, "version": VER, "jinja2": jinja2.__version__})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if urlparse(self.path).path != "/render":
            self._send(404, {"error": "not found"})
            return
        n = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(n).decode("utf-8", "replace")
        try:
            self._send(200, run_render(payload))
        except Exception as e:  # noqa: BLE001
            self._send(200, {"version": VER, "blocked": False, "error": f"harness: {e}", "output": None})


if __name__ == "__main__":
    if not os.environ.get("PCB_CANARY"):
        raise RuntimeError("PCB_CANARY not set (per-run flag token)")
    port = int(os.environ.get("HARNESS_PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
