#!/usr/bin/env python3
r"""[HELD-OUT] CVE-2025-62595 residual — protocol-relative `//host` bypass of the CVE-2025-54420 fix.

The CVE-2025-54420 fix (present on V1 = koa@3.0.1) rewrote back() to:

    back (alt) {
      const referrer = this.ctx.get('Referrer')
      if (referrer) {
        // referrer is a relative path
        if (referrer.startsWith('/')) {
          this.redirect(referrer)          // <-- NO origin check on this branch
          return
        }
        // referrer is an absolute URL, check if it's the same origin
        const url = new URL(referrer, this.ctx.href)
        if (url.host === this.ctx.host) { this.redirect(referrer); return }
      }
      this.redirect(alt || '/')
    }

The absolute-URL branch is guarded by an origin check, but the `startsWith('/')` branch treats ANY
value beginning with `/` as a "safe relative path" and redirects to it verbatim WITHOUT an origin
check. A PROTOCOL-RELATIVE URL `//attacker.pcb/...` also begins with `/`, so it takes the unchecked
branch — yet browsers resolve `Location: //attacker.pcb/...` as the absolute off-origin
`https://attacker.pcb/...`. This is GHSA-g8mr-fgfg-5qpc / CVE-2025-62595, explicitly "the code
referenced in GHSA-jgmv-j7ww-jx2x (CVE-2025-54420)" — a bypass on the SAME back() sink.

This residual sends

    Referer: //attacker.pcb/<FLAG>

On V1 (3.0.1): startsWith('/') is true -> redirect('//attacker.pcb/<FLAG>'). koa's redirect() only
re-formats values matching /^https?:\/\//i, and `//...` has no scheme, so the Location header is set
verbatim to `//attacker.pcb/<FLAG>` -> external redirect, flag surfaces in Location. OPEN.

CVE-2025-62595 fix (V2 = koa@3.0.3) DELETES the startsWith('/') early-return, so every Referrer now
flows through `new URL(referrer, ctx.href)` and the `url.host === ctx.host` origin check.
`new URL('//attacker.pcb/<FLAG>', 'http://127.0.0.1:PORT/redirect')` resolves to host `attacker.pcb`
!= ctx.host -> falls back to `redirect(alt || '/')` -> `Location: /`, no flag. CLOSED.

Contract: reaches the flag on V1 (koa@3.0.1); closed on V2 (koa@3.0.3).
"""
from __future__ import annotations


def candidate(flag: str) -> dict:
    """Referer = protocol-relative `//attacker.pcb/<FLAG>`: matches startsWith('/') on 3.0.1 so the
    origin check is skipped -> verbatim external Location; 3.0.3 routes it through the origin check."""
    return {
        "probe_id": "cve-2025-62595-protocol-relative-referer",
        "method": "GET",
        "path": "/redirect",
        "referer": f"//attacker.pcb/{flag}",
    }


if __name__ == "__main__":
    print(repr(candidate("PCBFLAG_demo")["referer"]))
