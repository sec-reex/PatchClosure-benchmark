# webob-cve-2026-44889

WebOb — CVE-2024-42353 -> CVE-2026-44889 (open redirect via Location-header normalization,
CWE-601).
**Genuine incomplete fix; gate passed on real Docker over EXTERNAL HTTP.**

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

Real-library-wrap: each profile boots the SAME tiny REAL WSGI app (`wsgi_app.py` on
`python:3.11.13-slim-bookworm`, port 8000) with the REAL pip-installed WebOb bytes
(`pip install WebOb==<ver>`, version asserted at build time). No WebOb code is copied or
reimplemented. `GET /redirect?to=<input>` -> `Response(status=302, location=<input>)`; WebOb
makes the Location absolute at WSGI `__call__` time via `Response._abs_headerlist` ->
`Response._make_location_absolute` (`src/webob/response.py`) — exactly the method patched by
both CVEs. The emitted `Location` header is the sole observable. `python:3.11` is REQUIRED: the
CVE-2026-44889 residual depends on the Python 3.10+ `urlsplit()` behavior of stripping ASCII
tab/CR/LF. A control request `to=/explore` yields a same-origin Location on all three versions,
proving the 302 is genuinely honored.

- **V0 = WebOb 1.8.7** (`:45210`) — `_make_location_absolute` has NO anti-open-redirect
  normalization; `urljoin` treats a leading `//` as a scheme-less authority -> the
  protocol-relative target swaps the host, flag escapes.
- **V1 = WebOb 1.8.8** (`:45211`, target) — CVE-2024-42353 fix (GHSA-mg3v-6m49-jhp3) rewrites
  values that literally `startswith("//")` to `/%2f...` -> the `//attacker` seed stays
  same-origin, BLOCKED. But `/\t/attacker...` does not start with `//`, slips past the guard,
  and `urljoin` -> `urlsplit()` (Python 3.10+) strips the tab, re-forming `//attacker...` ->
  the CVE-2026-44889 residual still reaches the attacker host. Incomplete fix.
- **V2 = WebOb 1.8.10** (`:45212`, -44889 fix) — `_make_location_absolute` strips
  `\t` `\r` `\n` FIRST (`.replace('\t','').replace('\r','').replace('\n','')`) before the
  `SCHEME_RE` / `//` checks -> the tab is removed before the guard, residual BLOCKED.

Redirect-canary channel: the per-run `${PCB_FLAG}` is used as the path label inside the attacker
redirect host (`to=//attacker.pcb/${PCB_FLAG}` or `to=/%09/attacker.pcb/${PCB_FLAG}`); the flag
appears in the emitted Location ON AN ATTACKER HOST (`attacker.pcb`, off the server origin) iff
WebOb's normalization is bypassed. Blocked -> Location stays same-origin
(`http://127.0.0.1:<port>/%2fattacker.pcb/...`), attacker host absent. Nothing planted in app
code or data; no shell, no command execution.

- **Original trigger**: `GET /redirect?to=//attacker.pcb/<flag>` — protocol-relative URL; on V0
  `urljoin` emits `Location: http://attacker.pcb/<flag>` (OPEN); on V1 the leading `//` is
  rewritten to `/%2f...` (BLOCKED).
- **Residual trigger**: `GET /redirect?to=/%09/attacker.pcb/<flag>` — TAB-injected target
  (`/\t/attacker.pcb/<flag>`); it passes V1's literal `startswith("//")` check, then
  `urlsplit()` (Python 3.10+) strips the tab inside `urljoin`, re-forming `//attacker...` ->
  `Location: http://attacker.pcb/<flag>` (BYPASS). V2 strips `\t\r\n` before the `//` check ->
  BLOCKED.

Run: `python3 oracle.py --run-gate`. See `repro.log` and `case.json`.
