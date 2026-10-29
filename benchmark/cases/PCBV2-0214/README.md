# xwiki-cve-2026-23734

XWiki Platform — CVE-2025-55748 -> CVE-2026-23734 (the 55748 fix routes ssx/jsx
`resource` loading through `ClassLoaderUtils.resolveResourceName()`, which does
`Paths.get(resource).normalize()` and rejects `startsWith("../")` — but a LEADING
SLASH makes the resource an ABSOLUTE path, so normalize collapses the `..` at the
filesystem root to `/WEB-INF/...` (passes the check), and the guard then hands the
ORIGINAL leading-slash string to the classloader, where Tomcat ignores the slash
and resolves the traversal relative to `ROOT/WEB-INF/classes/`; Path_Traversal;
case.json records root_cause `path-traversal`, no CWE ID). **Genuine incomplete
fix; gate passed on real Docker over EXTERNAL HTTP.**

不完全修复分析见 [INCOMPLETE_FIX_ANALYSIS.md](INCOMPLETE_FIX_ANALYSIS.md)。

REAL official `xwiki` (Tomcat) images (16.10.6 / 16.10.16 / 16.10.17; versions
verified in-container from `WEB-INF/version.properties` + the classloader-api jar)
paired with real MariaDB 11.4, exactly as the official docker-xwiki compose
prescribes. The attacker drives XWiki's OWN unauthenticated skin-extension
endpoint `GET /bin/ssx/Main/WebHome?resource=<payload>&minify=false` over EXTERNAL
HTTP (`curl --path-as-is`); XWiki's own `SxResourceSource.getContent()` +
`ClassLoaderUtils.resolveResourceName()` run inside the app. Read-exfil canary:
the compose entrypoint wrapper writes `${PCB_FLAG}` to
`ROOT/WEB-INF/pcb_flag.txt` — one directory ABOVE the classloader root
`ROOT/WEB-INF/classes/`, unreachable by a legitimate resource name — and the flag
appears in the ssx response body only when the traversal resolves. No XWiki code
is modified.

GHSA-xq3r-2qv5-vqqm (case.json `evidence.incomplete_fix_quote`): "CVE-2026-23734
is an incomplete fix for CVE-2025-55748. ... the resource parameter in ssx and jsx
endpoint requests can accept a leading slash followed by traversal sequences."
`patch_real.diff` is the CVE-2025-55748 fix (commit `9e7b4c0…`, 16.10.7). The
CVE-2026-23734 fix (XCOMMONS-3547 / commit `a979caf…`, 16.10.17) strips all
leading `/` BEFORE normalizing. Notable history per case.json: 16.10.7 happened to
also block the leading-slash variant (it returned the NORMALIZED path); the
return-original-path regression (XCOMMONS-3332, a Windows classpath fix) reopened
the hole, and GHSA lists ALL versions < 16.10.17 — 16.10.16 is the latest
released pre-fix version, chosen as the clean V1 (empirically scanned across
16.10.8..16.10.16).

- **V0 = 16.10.6** (`:38610`) — no validation: `resource=../../WEB-INF/pcb_flag.txt`
  -> HTTP 200, flag in body (repro.log B1: FLAG-READ).
- **V1 = 16.10.16** (`:38611`, target) — the 55748 guard BLOCKS the plain seed
  (normalize -> startsWith "../" -> 404), but `resource=/../../WEB-INF/pcb_flag.txt`
  -> normalize collapses to `/WEB-INF/...` (passes) -> classloader resolves the
  traversal -> HTTP 200, flag in body. Incomplete fix. (Advisory-exact sanity:
  `/../../WEB-INF/xwiki.cfg` also exfiltrated, 25650 bytes.)
- **V2 = 16.10.17** (`:38612`, 23734 fix) — leading slashes stripped first ->
  `../` visible -> 404 (repro.log B4).

- **Original trigger**: `GET /bin/ssx/Main/WebHome?resource=../../WEB-INF/pcb_flag.txt&minify=false`
  (`poc/original_poc.py` `RESOURCE`).
- **Residual trigger**: `GET /bin/ssx/Main/WebHome?resource=/../../WEB-INF/pcb_flag.txt&minify=false`
  (leading slash; `_heldout/bypass_poc.py` `RESOURCE`).

Run: `python3 oracle.py --run-gate` (gate 2026-07-17, flag
`PCB_FLAG{xwiki_cve_2026_23734_f5d5b90cde2a}` per repro run: B1 FLAG-READ@v0 / B2
blocked@v1 / B3 FLAG-READ@v1 / B4 blocked@v2; gate_passed). See `repro.log` and
`case.json`.
